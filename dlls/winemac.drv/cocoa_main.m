/*
 * MACDRV Cocoa initialization code
 *
 * Copyright 2011, 2012, 2013 Ken Thomases for CodeWeavers Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#import <AppKit/AppKit.h>
#import <Carbon/Carbon.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <signal.h>
#include <unistd.h>

#include "macdrv_cocoa.h"
#import "cocoa_app.h"

#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"


/* Condition values for an NSConditionLock. Used to signal between run_cocoa_app
   and macdrv_start_cocoa_app so the latter knows when the former is running
   the application event loop. */
enum {
    COCOA_APP_NOT_RUNNING,
    COCOA_APP_RUNNING,
};


struct cocoa_app_startup_info {
    NSConditionLock*    lock;
    unsigned long long  tickcount;
    uint64_t            uptime_ns;
    BOOL                success;
};


/* Forward decl: defined further below, called by run_cocoa_app at
 * NSApp-launch time. */
static void install_proton_force_quit_hotkey(void);


/***********************************************************************
 *              run_cocoa_app
 *
 * Transforms the main thread from merely idling in its run loop to
 * being a Cocoa application running its event loop.
 *
 * This will be the perform callback of a custom run loop source that
 * will be scheduled in the main thread's run loop from a secondary
 * thread by macdrv_start_cocoa_app.  This function communicates that
 * it has successfully started the application by changing the condition
 * of a shared NSConditionLock, passed in via the info parameter.
 *
 * This function never returns.  It's the new permanent home of the
 * main thread.
 */
static void run_cocoa_app(void* info)
{
    struct cocoa_app_startup_info* startup_info = info;
    NSConditionLock* lock = startup_info->lock;
    BOOL created_app = FALSE;

    @autoreleasepool
    {
        if (!NSApp)
        {
            [WineApplication sharedApplication];
            created_app = TRUE;
        }

        if ([NSApp respondsToSelector:@selector(setWineController:)])
        {
            WineApplicationController* controller = [WineApplicationController sharedController];
            [NSApp setWineController:controller];
            [controller computeEventTimeAdjustmentFromTicks:startup_info->tickcount uptime:startup_info->uptime_ns];
            startup_info->success = TRUE;
        }

        /* Retain the lock while we're using it, so macdrv_start_cocoa_app()
           doesn't deallocate it in the middle of us unlocking it. */
        [lock retain];
        [lock lock];
        [lock unlockWithCondition:COCOA_APP_RUNNING];
        [lock release];
    }

    if (created_app && startup_info->success)
    {
        @autoreleasepool
        {
            install_proton_force_quit_hotkey();
            /* Never returns */
            [NSApp run];
        }
    }
}

/***********************************************************************
 *              proton_force_quit_hotkey_handler
 *
 * Carbon hotkey callback. Fires on Cmd+Shift+Q at the system level
 * regardless of which Wine window has focus, even in fullscreen.
 * SIGTERMs the wine process so the normal signal-handler exit path
 * runs (audio stop, etc.).
 */
static OSStatus proton_force_quit_hotkey_handler(EventHandlerCallRef nextHandler,
                                                  EventRef event, void *userData)
{
    EventHotKeyID hkID;
    OSStatus s = GetEventParameter(event, kEventParamDirectObject, typeEventHotKeyID,
                                    NULL, sizeof(hkID), NULL, &hkID);
    if (s == noErr && hkID.signature == 'PMW1' && hkID.id == 1) {
        fprintf(stderr,
                "winemac: PROTON_AUTO_EXIT - Cmd+Shift+Q force-quit hotkey, SIGTERM self (pid=%d)\n",
                getpid());
        kill(getpid(), SIGTERM);
    }
    return noErr;
}

/***********************************************************************
 *              install_proton_force_quit_hotkey
 *
 * Register Cmd+Shift+Q as a Carbon system-level hotkey. Only active
 * when PROTON_AUTO_EXIT_ON_LAST_WINDOW=1 is set. Carbon hotkeys
 * bypass per-app keyboard capture and fire from any input state
 * including fullscreen, where Dock/menu-bar/Cmd-Q via menu are all
 * unreachable. Companion to the kAEQuit->SIGTERM path in
 * applicationShouldTerminate.
 */
static void install_proton_force_quit_hotkey(void)
{
    static int installed = 0;
    if (installed) return;

    const char *env = getenv("PROTON_AUTO_EXIT_ON_LAST_WINDOW");
    if (!env || env[0] == '0' || env[0] == '\0') return;

    EventTypeSpec eventType;
    eventType.eventClass = kEventClassKeyboard;
    eventType.eventKind = kEventHotKeyPressed;
    OSStatus s = InstallApplicationEventHandler(&proton_force_quit_hotkey_handler,
                                                 1, &eventType, NULL, NULL);
    if (s != noErr) {
        fprintf(stderr, "winemac: failed to install hotkey handler (status=%d)\n", (int)s);
        return;
    }

    EventHotKeyID hkID;
    hkID.signature = 'PMW1';
    hkID.id = 1;
    EventHotKeyRef hkRef;
    /* keyCode 0x0C = Q on every Mac keyboard layout (it's a physical key
     * code, not a character). cmdKey | shiftKey selects modifier flags. */
    s = RegisterEventHotKey(0x0C, cmdKey | shiftKey, hkID,
                            GetApplicationEventTarget(), 0, &hkRef);
    if (s != noErr) {
        fprintf(stderr, "winemac: failed to register Cmd+Shift+Q hotkey (status=%d)\n", (int)s);
        return;
    }
    installed = 1;
    fprintf(stderr, "winemac: PROTON_AUTO_EXIT - Cmd+Shift+Q force-quit hotkey installed\n");
}


/***********************************************************************
 *              macdrv_start_cocoa_app
 *
 * Tells the main thread to transform itself into a Cocoa application.
 *
 * Returns 0 on success, non-zero on failure.
 */
int macdrv_start_cocoa_app(unsigned long long tickcount)
{
@autoreleasepool
{
    int ret = -1;
    CFRunLoopSourceRef source;
    struct cocoa_app_startup_info startup_info;
    uint64_t uptime_mach = mach_absolute_time();
    mach_timebase_info_data_t mach_timebase;
    NSDate* timeLimit;
    CFRunLoopSourceContext source_context = { 0 };

    /* Make sure Cocoa is in multi-threading mode by detaching a
       do-nothing thread. */
    [NSThread detachNewThreadSelector:@selector(self)
                             toTarget:[NSThread class]
                           withObject:nil];

    startup_info.lock = [[NSConditionLock alloc] initWithCondition:COCOA_APP_NOT_RUNNING];
    startup_info.tickcount = tickcount;
    startup_info.success = FALSE;

    mach_timebase_info(&mach_timebase);
    startup_info.uptime_ns = uptime_mach * mach_timebase.numer / mach_timebase.denom;

    timeLimit = [NSDate dateWithTimeIntervalSinceNow:5];

    source_context.info = &startup_info;
    source_context.perform = run_cocoa_app;
    source = CFRunLoopSourceCreate(NULL, 0, &source_context);

    if (source && startup_info.lock && timeLimit)
    {
        CFRunLoopAddSource(CFRunLoopGetMain(), source, kCFRunLoopCommonModes);
        CFRunLoopSourceSignal(source);
        CFRunLoopWakeUp(CFRunLoopGetMain());

        if ([startup_info.lock lockWhenCondition:COCOA_APP_RUNNING beforeDate:timeLimit])
        {
            [startup_info.lock unlock];
            ret = !startup_info.success;
        }
    }

    if (source)
        CFRelease(source);
    [startup_info.lock release];
    return ret;
}
}
