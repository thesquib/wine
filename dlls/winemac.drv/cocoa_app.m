/*
 * MACDRV Cocoa application class
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

#import "cocoa_app.h"
#import "cocoa_cursorclipping.h"
#import "cocoa_event.h"
#import "cocoa_window.h"

#include <signal.h>   /* kill() - used by the PROTON_AUTO_EXIT_ON_LAST_WINDOW
                       * kAEQuit -> SIGTERM hook in applicationShouldTerminate */

#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"


static NSString* const WineAppWaitQueryResponseMode = @"WineAppWaitQueryResponseMode";

// Private notifications that are reliably dispatched when a window is moved by dragging its titlebar.
// The object of the notification is the window being dragged.
// Available in macOS 10.12+
static NSString* const NSWindowWillStartDraggingNotification = @"NSWindowWillStartDraggingNotification";
static NSString* const NSWindowDidEndDraggingNotification = @"NSWindowDidEndDraggingNotification";

// Internal distributed notification to handle cooperative app activation in Sonoma.
static NSString* const WineAppWillActivateNotification = @"WineAppWillActivateNotification";
static NSString* const WineActivatingAppPIDKey = @"ActivatingAppPID";
static NSString* const WineActivatingAppPrefixKey = @"ActivatingAppPrefix";
static NSString* const WineActivatingAppConfigDirKey = @"ActivatingAppConfigDir";


bool macdrv_err_on;

/* File-scope tracking for FPS-mode mouse disassociation so we can revert on
 * process exit. The mouseMoved handler toggles this when entering/leaving
 * FPS-style relative-motion mode. If a game exits without a clean Cocoa
 * teardown (e.g. Skyrim's in-game Quit) the mouseMoved transitions never
 * fire back to NO, leaving the system mouse disassociated and the run loop
 * waiting for events that never arrive. macdrv_restore_mouse_association()
 * is registered via atexit() in macdrv_init so any process exit re-couples
 * the mouse + cursor unconditionally. */
BOOL macdrv_mouse_disassociated = NO;

void macdrv_restore_mouse_association(void)
{
    /* Safe to call from any thread / context, including atexit on a
     * non-main thread. CGAssociateMouseAndMouseCursorPosition is a
     * lightweight CG call - no Cocoa locking required. */
    if (macdrv_mouse_disassociated)
    {
        CGAssociateMouseAndMouseCursorPosition(true);
        macdrv_mouse_disassociated = NO;
    }
}

/* ---------------------------------------------------------------------
 * Strategy E.1 - Vulkan-path layer-host broadcast.
 *
 * winemac.drv's Vulkan path creates a CAMetalLayer inside a WineMetalView
 * which lives as a subview of the surface->cocoa_view. The cocoa_view is
 * normally inserted into the WineContentView via macdrv_set_view_superview
 * during macdrv_client_surface_update - but only if get_win_data(toplevel)
 * succeeds. When the toplevel HWND belongs to another Wine process (or is
 * not yet registered in this process's win_datas) the update silently
 * returns and the cocoa_view is never parented. MoltenVK then renders into
 * a layer that's offscreen, producing DOOM's "title bar but no content"
 * symptom.
 *
 * The fallback mirrors DXMT's existing same-process direct-attach trick:
 * wrap the CAMetalLayer in a CAContext and post a
 * DXMTRemoteLayerHostRequest notification. The existing handleDXMT...
 * observer will (via macdrv_resolve_hwnd_for_hosting) find a visible
 * WineContentView in this or a sibling process and attach the layer
 * directly (same process) or via CALayerHost(contextId:) (cross process).
 *
 * The notification name is reused intentionally: the observer's contract
 * is HWND-keyed and protocol-agnostic - it doesn't care whether the layer
 * came from DXMT or winevulkan.
 * ------------------------------------------------------------------- */
typedef uint32_t CGSConnectionID;
extern CGSConnectionID CGSMainConnectionID(void);

@interface CAContext : NSObject
+ (CAContext *)contextWithCGSConnection:(CGSConnectionID)cid options:(NSDictionary *)opts;
@property (retain) CALayer *layer;
@property (readonly) uint32_t contextId;
@end

/* Forward declaration so the E.1 handler can probe whether the target view is
 * a live software paint target (WineContentView lives in cocoa_window.m, same
 * unixlib). See -[WineContentView hasLiveColorImage]. */
@interface WineContentView : NSView
- (BOOL) hasLiveColorImage;
@end

/* Shared between the broadcast retry timer and the
 * handleDXMTRemoteLayerHostRequest: handler. The handler adds the hwnd to
 * this set when it successfully hosts the layer in this process; the retry
 * timer reads it and bails. Both run on the main queue, so no locking is
 * required. */
static NSMutableSet *s_e1AttachedHwnds = nil;

/* Build-fixup (proton-darwin DOOM-bisect 2026-05-16): see .parked/README.md */
void macdrv_remove_orphan_views_for_view(void *opaque_view, const char *call_site)
{
    (void)opaque_view; (void)call_site;
}

/* Bug (Proton macOS) 2026-05-18 queued 0052: PROTON_E1_DIAG.
 * Cached single getenv. Log-only, default off. Discriminates among the
 * four KCD2-class failure modes for the E.1 cross-process layer-host
 * path (see patch commit message for the (A)-(D) classification). */
static int proton_e1_diag_enabled(void)
{
    static int cached = -1;
    if (cached < 0) {
        const char *v = getenv("PROTON_E1_DIAG");
        cached = (v && *v && strcmp(v, "0") != 0) ? 1 : 0;
    }
    return cached;
}

/* Bug (Proton macOS) 2026-05-23 overlay 0050 (v2): per-appid skip.
 * DOOM Eternal (782330) hit kIOGPUCommandBufferCallbackErrorInnocentVictim
 * with the original setPresentationOptions-based 0050 (2026-05-14 regression,
 * commit 603bf61). The v2 patch uses [NSMenu setMenuBarVisible:] which is
 * hypothesised safer, but as a safety belt we hard-skip Eternal so even if
 * the API turns out to be equivalent under the hood, Eternal is unaffected.
 * Cached single getenv to keep the hot path free of repeat string compares. */
/* PROTON_FORCE_MENUBAR_HIDE: bypass the per-appid menubar-hide skip so the
 * menubar auto-hides even for a title on the skip list (DOOM 2016 379720 was
 * added to the skip by 0070 to dodge the alt-tab crash). Used to test whether,
 * with PROTON_KEEP_FULLSCREEN_MAPPED keeping the window stable, the single
 * deferred setMenuBarVisible:NO now lands cleanly on KK instead of dropping the
 * in-flight Vulkan drawable (the DOOM Eternal MAILBOX black-screen). Cached
 * single getenv. Tag [FORCE-MENUBAR-HIDE]. */
static int proton_force_menubar_hide(void)
{
    static int cached = -1;
    if (cached < 0) {
        const char *v = getenv("PROTON_FORCE_MENUBAR_HIDE");
        cached = (v && *v && *v != '0') ? 1 : 0;
    }
    return cached;
}

static int proton_menubar_hide_skip_appid(void)
{
    static int cached = -1;
    if (cached < 0) {
        const char *id = getenv("SteamAppId");
        const char *skip = getenv("PROTON_NO_MENUBAR_HIDE");
        /* setMenuBarVisible: drives a WindowServer compositor reconfigure.
         * For some fullscreen titles this re-enters the fullscreen-state
         * detection and flaps anyFullscreen 1<->0, re-firing adjustWindowLevels
         * -> updateMenuBarHiding forever (DOOM Eternal black-screens; Detroit:
         * Become Human melts down at 600%+ CPU into a user_lock convoy + window
         * death). Skip the toggle for known-bad appids, or via env so a recipe
         * can opt out without a rebuild. */
        cached = ((skip && *skip && *skip != '0') ||
                  (id && (!strcmp(id, "782330") ||    /* DOOM Eternal */
                          !strcmp(id, "1222140") ||   /* Detroit: Become Human */
                          !strcmp(id, "379720")))) ? 1 : 0;  /* DOOM 2016 (alt-tab crash) */
    }
    return cached;
}

__attribute__((visibility("default")))
void macdrv_broadcast_vulkan_layer_host_request(void *hwnd, void *metal_layer)
{
    fprintf(stderr, "winemac:VK broadcast ENTER hwnd=%p layer=%p isMain=%d\n",
            hwnd, metal_layer, (int)[NSThread isMainThread]);
    if (!hwnd || !metal_layer) {
        fprintf(stderr, "winemac:E.1-vulkan - refusing to broadcast hwnd=%p layer=%p\n",
                hwnd, metal_layer);
        return;
    }

    /* Track per-hwnd state so we don't re-arm the retry timer for every
     * surface_update call. The CAContext must be retained for the lifetime
     * of the layer (its dealloc breaks hosting). */
    static NSMutableDictionary *ctxByHwnd = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ ctxByHwnd = [[NSMutableDictionary alloc] init]; });
    fprintf(stderr, "winemac:VK broadcast STEPB1 ctxByHwnd=%p\n", ctxByHwnd);

    @autoreleasepool {
        NSNumber *key = @((uintptr_t)hwnd);
        BOOL firstTime = (ctxByHwnd[key] == nil);
        fprintf(stderr, "winemac:VK broadcast STEPB2 firstTime=%d\n", firstTime);

        __block uint32_t contextId = 0;
        if (firstTime) {
            /* CAContext.contextWithCGSConnection: must run on the main
             * thread - it touches the WindowServer connection. The first
             * caller is typically Wine's render thread, so dispatch sync
             * to main. */
            __block CAContext *ctx = nil;
            dispatch_block_t make = ^{
                fprintf(stderr, "winemac:VK broadcast STEPB3a calling CAContext contextWithCGSConnection\n");
                /* Bug (Proton macOS) 2026-04-29: this code is MRC, not ARC.
                 * `+contextWithCGSConnection:options:` returns an autoreleased
                 * object. The dispatch_sync's main-thread autorelease pool
                 * drains when the block returns, releasing the CAContext -
                 * leaving `ctx` dangling. The next access (`ctxByHwnd[key] = ctx`
                 * outside the block) then fault with STATUS_ACCESS_VIOLATION
                 * (0xc0000005), aborting `vkCreateWin32SurfaceKHR`. Manual
                 * retain inside the block keeps the object alive past the
                 * dispatch boundary; the dictionary's strong reference takes
                 * over ownership when ctx is stored. */
                ctx = [[CAContext contextWithCGSConnection:CGSMainConnectionID() options:nil] retain];
                fprintf(stderr, "winemac:VK broadcast STEPB3b ctx=%p (retained)\n", ctx);
                ctx.layer = (__bridge CALayer *)metal_layer;
                fprintf(stderr, "winemac:VK broadcast STEPB3c ctx.layer set\n");
                contextId = ctx.contextId;
                fprintf(stderr, "winemac:VK broadcast STEPB3d contextId=%u\n", contextId);
            };
            if ([NSThread isMainThread]) {
                fprintf(stderr, "winemac:VK broadcast STEPB3 on main thread, calling make() inline\n");
                make();
            } else {
                fprintf(stderr, "winemac:VK broadcast STEPB3 not main, dispatch_sync to main\n");
                dispatch_sync(dispatch_get_main_queue(), make);
                fprintf(stderr, "winemac:VK broadcast STEPB3 dispatch_sync returned\n");
            }

            if (!ctx) {
                fprintf(stderr, "winemac:E.1-vulkan - failed to create CAContext for hwnd=%p\n", hwnd);
                return;
            }
            ctxByHwnd[key] = ctx;
            fprintf(stderr, "winemac:E.1-vulkan - created CAContext id=%u for layer=%p hwnd=%p\n",
                    contextId, metal_layer, hwnd);
        } else {
            CAContext *existing = ctxByHwnd[key];
            contextId = existing.contextId;
        }

        __block uintptr_t capturedHwnd = (uintptr_t)hwnd;
        __block uintptr_t capturedLayer = (uintptr_t)metal_layer;
        __block uint32_t capturedCtx = contextId;
        __block int capturedPid = getpid();
        void (^doBroadcast)(void) = ^{
            NSDictionary *info = @{
                @"hwnd": @(capturedHwnd),
                @"contextId": @(capturedCtx),
                @"pid": @(capturedPid),
                @"layerPtr": @(capturedLayer)
            };
            [[NSDistributedNotificationCenter defaultCenter]
                postNotificationName:@"DXMTRemoteLayerHostRequest"
                              object:nil
                            userInfo:info
                  deliverImmediately:YES];
        };
        doBroadcast();
        fprintf(stderr, "winemac:E.1-vulkan - broadcast hwnd=%p ctxId=%u pid=%d layer=%p (firstTime=%d)\n",
                hwnd, contextId, getpid(), metal_layer, firstTime);

        /* Queued 0052 [E1-DIAG]: anchor publish timing for receive correlation. */
        if (proton_e1_diag_enabled()) {
            fprintf(stderr, "winemac:[E1-DIAG] publish pid=%d hwnd=%p layer=%p firstTime=%d ctxId=%u\n",
                    getpid(), hwnd, metal_layer, (int)firstTime, contextId);
            fflush(stderr);
        }

        /* On the first broadcast, arm the same retry pattern as DXMT - the
         * target NSWindow may not be on_screen yet when surface_create
         * fires. Retry every 500ms for up to 30 seconds, but ABORT THE RETRY
         * as soon as the same-process handler reports a successful attach.
         *
         * Bug (Proton macOS) 2026-05-05: without the abort, every retry fires
         * a fresh broadcast that re-runs the attach handler in every receiver
         * process. The re-attach re-sets layer.frame / contentsScale /
         * autoresizingMask on the live CAMetalLayer 60 times across 30s,
         * which the user perceives as constant flicker (Hades main menu).
         * Cmd-Tab "fixed" it because the retry timer naturally ages out
         * before focus returned. The handler now stamps `s_e1AttachedHwnds`
         * with the hwnd on a successful attach (line ~2410); we check it
         * here before re-broadcasting. */
        if (firstTime) {
            __block int retryCount = 0;
            __block void (^retryBlock)(void);
            uintptr_t hwndKeyVal = (uintptr_t)hwnd;
            void (^retryBlockContent)(void) = ^{
                retryCount++;
                if ([s_e1AttachedHwnds containsObject:@(hwndKeyVal)]) {
                    fprintf(stderr,
                            "winemac:E.1-vulkan - retry abort: hwnd=%p already attached (after %d retries)\n",
                            (void *)hwndKeyVal, retryCount);
                    return;
                }
                doBroadcast();
                if (retryCount < 60) {
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                                 (int64_t)(0.5 * NSEC_PER_SEC)),
                                   dispatch_get_main_queue(), retryBlock);
                }
            };
            retryBlock = [retryBlockContent copy];
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                         (int64_t)(0.5 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), retryBlock);
        }
    }
}


#if !defined(MAC_OS_VERSION_14_0) || MAC_OS_X_VERSION_MAX_ALLOWED < MAC_OS_VERSION_14_0
@interface NSApplication (CooperativeActivationSelectorsForOldSDKs)

    - (void)activate;
    - (void)yieldActivationToApplication:(NSRunningApplication *)application;
    - (void)yieldActivationToApplicationWithBundleIdentifier:(NSString *)bundleIdentifier;

@end

@interface NSRunningApplication (CooperativeActivationSelectorsForOldSDKs)

    - (BOOL)activateFromApplication:(NSRunningApplication *)application
                            options:(NSApplicationActivationOptions)options;

@end
#endif


/***********************************************************************
 *              WineLocalizedString
 *
 * Look up a localized string by its ID in the dictionary.
 */
static NSString* WineLocalizedString(unsigned int stringID)
{
    return ((NSDictionary*)localized_strings)[@(stringID)];
}


@implementation WineApplication

@synthesize wineController;

    - (void) sendEvent:(NSEvent*)anEvent
    {
        if (![wineController handleEvent:anEvent])
        {
            [super sendEvent:anEvent];
            [wineController didSendEvent:anEvent];
        }
    }

    - (void) setWineController:(WineApplicationController*)newController
    {
        wineController = newController;
        [self setDelegate:wineController];
    }

@end


@interface WineApplicationController ()

@property (readwrite, copy, nonatomic) NSEvent* lastFlagsChanged;
@property (copy, nonatomic) NSArray* cursorFrames;
@property (retain, nonatomic) NSTimer* cursorTimer;
@property (retain, nonatomic) NSCursor* cursor;
@property (retain, nonatomic) NSImage* applicationIcon;
@property (readonly, nonatomic) BOOL inputSourceIsInputMethod;
@property (retain, nonatomic) WineWindow* mouseCaptureWindow;
    /* YES when the current capture is Wine's own move/size loop (GUI_INMOVESIZE)
     * rather than an app calling SetCapture for mouse-look. See fpsModeActive. */
@property (nonatomic) BOOL mouseCaptureIsMoveSize;

    - (void) setupObservations;
    - (void) applicationDidBecomeActive:(NSNotification *)notification;
    - (void) updateMenuBarHiding;
    - (void) handleDXMTRemoteLayerHostRequest:(NSNotification *)note;

    static void PerformRequest(void *info);

@end


@implementation WineApplicationController

    @synthesize keyboardType, lastFlagsChanged;
    @synthesize applicationIcon;
    @synthesize cursorFrames, cursorTimer, cursor;
    @synthesize mouseCaptureWindow;
    @synthesize mouseCaptureIsMoveSize;
    @synthesize lastSetCursorPositionTime;

    + (void) initialize
    {
        if (self == [WineApplicationController class])
        {
            NSDictionary<NSString *, id> *defaults =
            @{
                @"NSQuotedKeystrokeBinding" : @"",
                    @"NSRepeatCountBinding" : @"",
                @"ApplePressAndHoldEnabled" : @NO
            };

            [[NSUserDefaults standardUserDefaults] registerDefaults:defaults];

            [NSWindow setAllowsAutomaticWindowTabbing:NO];
        }
    }

    + (WineApplicationController*) sharedController
    {
        static WineApplicationController* sharedController;
        static dispatch_once_t once;

        dispatch_once(&once, ^{
            sharedController = [[self alloc] init];
        });

        return sharedController;
    }

    - (id) init
    {
        self = [super init];
        if (self != nil)
        {
            CFRunLoopSourceContext context = { 0 };
            context.perform = PerformRequest;
            requestSource = CFRunLoopSourceCreate(NULL, 0, &context);
            if (!requestSource)
            {
                [self release];
                return nil;
            }
            CFRunLoopAddSource(CFRunLoopGetMain(), requestSource, kCFRunLoopCommonModes);
            CFRunLoopAddSource(CFRunLoopGetMain(), requestSource, (CFStringRef)WineAppWaitQueryResponseMode);

            requests =  [[NSMutableArray alloc] init];
            requestsManipQueue = dispatch_queue_create("org.winehq.WineAppRequestManipQueue", NULL);

            eventQueues = [[NSMutableArray alloc] init];
            eventQueuesLock = [[NSLock alloc] init];

            keyWindows = [[NSMutableArray alloc] init];

            originalDisplayModes = [[NSMutableDictionary alloc] init];
            latentDisplayModes = [[NSMutableDictionary alloc] init];

            windowsBeingDragged = [[NSMutableSet alloc] init];

            if (!requests || !requestsManipQueue || !eventQueues || !eventQueuesLock ||
                !keyWindows || !originalDisplayModes || !latentDisplayModes)
            {
                [self release];
                return nil;
            }

            [self setupObservations];

            keyboardType = LMGetKbdType();

            if ([NSApp isActive])
                [self applicationDidBecomeActive:nil];
        }
        return self;
    }

    - (void) dealloc
    {
        [windowsBeingDragged release];
        [cursor release];
        [screenFrameCGRects release];
        [applicationIcon release];
        [clipCursorHandler release];
        [cursorTimer release];
        [cursorFrames release];
        [latentDisplayModes release];
        [originalDisplayModes release];
        [keyWindows release];
        [eventQueues release];
        [eventQueuesLock release];
        if (requestsManipQueue) dispatch_release(requestsManipQueue);
        [requests release];
        if (requestSource)
        {
            CFRunLoopSourceInvalidate(requestSource);
            CFRelease(requestSource);
        }
        [super dealloc];
    }

    - (void) transformProcessToForeground:(BOOL)activateIfTransformed
    {
        if ([NSApp activationPolicy] != NSApplicationActivationPolicyRegular)
        {
            NSMenu* mainMenu;
            NSMenu* submenu;
            NSString* bundleName;
            NSString* title;
            NSMenuItem* item;

            [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];

            if (activateIfTransformed)
                [self tryToActivateIgnoringOtherApps:YES];

            if (!enable_app_nap)
            {
                [[[NSProcessInfo processInfo] beginActivityWithOptions:NSActivityUserInitiatedAllowingIdleSystemSleep
                                                                reason:@"Running Windows program"] retain]; // intentional leak
            }

            mainMenu = [[[NSMenu alloc] init] autorelease];

            // Application menu
            submenu = [[[NSMenu alloc] initWithTitle:WineLocalizedString(STRING_MENU_WINE)] autorelease];
            bundleName = [[NSBundle mainBundle] objectForInfoDictionaryKey:(NSString*)kCFBundleNameKey];

            if ([bundleName length])
                title = [NSString stringWithFormat:WineLocalizedString(STRING_MENU_ITEM_HIDE_APPNAME), bundleName];
            else
                title = WineLocalizedString(STRING_MENU_ITEM_HIDE);
            item = [submenu addItemWithTitle:title action:@selector(hide:) keyEquivalent:@""];

            item = [submenu addItemWithTitle:WineLocalizedString(STRING_MENU_ITEM_HIDE_OTHERS)
                                      action:@selector(hideOtherApplications:)
                               keyEquivalent:@"h"];
            [item setKeyEquivalentModifierMask:NSEventModifierFlagCommand | NSEventModifierFlagOption];

            item = [submenu addItemWithTitle:WineLocalizedString(STRING_MENU_ITEM_SHOW_ALL)
                                      action:@selector(unhideAllApplications:)
                               keyEquivalent:@""];

            [submenu addItem:[NSMenuItem separatorItem]];

            if ([bundleName length])
                title = [NSString stringWithFormat:WineLocalizedString(STRING_MENU_ITEM_QUIT_APPNAME), bundleName];
            else
                title = WineLocalizedString(STRING_MENU_ITEM_QUIT);
            item = [submenu addItemWithTitle:title action:@selector(terminate:) keyEquivalent:@"q"];
            [item setKeyEquivalentModifierMask:NSEventModifierFlagCommand | NSEventModifierFlagOption];
            item = [[[NSMenuItem alloc] init] autorelease];
            [item setTitle:WineLocalizedString(STRING_MENU_WINE)];
            [item setSubmenu:submenu];
            [mainMenu addItem:item];

            // Window menu
            submenu = [[[NSMenu alloc] initWithTitle:WineLocalizedString(STRING_MENU_WINDOW)] autorelease];
            [submenu addItemWithTitle:WineLocalizedString(STRING_MENU_ITEM_MINIMIZE)
                               action:@selector(performMiniaturize:)
                        keyEquivalent:@""];
            [submenu addItemWithTitle:WineLocalizedString(STRING_MENU_ITEM_ZOOM)
                               action:@selector(performZoom:)
                        keyEquivalent:@""];
            item = [submenu addItemWithTitle:WineLocalizedString(STRING_MENU_ITEM_ENTER_FULL_SCREEN)
                                      action:@selector(toggleFullScreen:)
                               keyEquivalent:@"f"];
            [item setKeyEquivalentModifierMask:NSEventModifierFlagCommand |
                                               NSEventModifierFlagOption |
                                               NSEventModifierFlagControl];
            [submenu addItem:[NSMenuItem separatorItem]];
            [submenu addItemWithTitle:WineLocalizedString(STRING_MENU_ITEM_BRING_ALL_TO_FRONT)
                               action:@selector(arrangeInFront:)
                        keyEquivalent:@""];
            item = [[[NSMenuItem alloc] init] autorelease];
            [item setTitle:WineLocalizedString(STRING_MENU_WINDOW)];
            [item setSubmenu:submenu];
            [mainMenu addItem:item];

            [NSApp setMainMenu:mainMenu];
            [NSApp setWindowsMenu:submenu];

            [NSApp setApplicationIconImage:self.applicationIcon];
        }
    }

    - (BOOL) waitUntilQueryDone:(bool*)done timeout:(NSDate*)timeout processEvents:(BOOL)processEvents
    {
        PerformRequest(NULL);

        do
        {
            if (processEvents)
            {
                @autoreleasepool
                {
                    NSEvent* event = [NSApp nextEventMatchingMask:NSEventMaskAny
                                                        untilDate:timeout
                                                           inMode:NSDefaultRunLoopMode
                                                          dequeue:YES];
                    if (event)
                        [NSApp sendEvent:event];
                }
            }
            else
                [[NSRunLoop currentRunLoop] runMode:WineAppWaitQueryResponseMode beforeDate:timeout];
        } while (!*done && [timeout timeIntervalSinceNow] >= 0);

        return *done;
    }

    - (BOOL) registerEventQueue:(WineEventQueue*)queue
    {
        [eventQueuesLock lock];
        [eventQueues addObject:queue];
        [eventQueuesLock unlock];
        return TRUE;
    }

    - (void) unregisterEventQueue:(WineEventQueue*)queue
    {
        [eventQueuesLock lock];
        [eventQueues removeObjectIdenticalTo:queue];
        [eventQueuesLock unlock];
    }

    - (void) computeEventTimeAdjustmentFromTicks:(unsigned long long)tickcount uptime:(uint64_t)uptime_ns
    {
        eventTimeAdjustment = (tickcount / 1000.0) - (uptime_ns / (double)NSEC_PER_SEC);
    }

    - (double) ticksForEventTime:(NSTimeInterval)eventTime
    {
        return (eventTime + eventTimeAdjustment) * 1000;
    }

    /* Invalidate old focus offers across all queues. */
    - (void) invalidateGotFocusEvents
    {
        WineEventQueue* queue;

        windowFocusSerial++;

        [eventQueuesLock lock];
        for (queue in eventQueues)
        {
            [queue discardEventsMatchingMask:event_mask_for_type(WINDOW_GOT_FOCUS)
                                   forWindow:nil];
        }
        [eventQueuesLock unlock];
    }

    - (void) windowGotFocus:(WineWindow*)window
    {
        macdrv_event* event;

        [self invalidateGotFocusEvents];

        event = macdrv_create_event(WINDOW_GOT_FOCUS, window);
        event->window_got_focus.serial = windowFocusSerial;
        if (triedWindows)
            event->window_got_focus.tried_windows = [triedWindows retain];
        else
            event->window_got_focus.tried_windows = [[NSMutableSet alloc] init];
        [window.queue postEvent:event];
        macdrv_release_event(event);
    }

    - (void) windowRejectedFocusEvent:(const macdrv_event*)event
    {
        if (event->window_got_focus.serial == windowFocusSerial)
        {
            NSMutableArray* windows = [keyWindows mutableCopy];
            NSNumber* windowNumber;
            WineWindow* window;

            for (windowNumber in [NSWindow windowNumbersWithOptions:NSWindowNumberListAllSpaces])
            {
                window = (WineWindow*)[NSApp windowWithWindowNumber:[windowNumber integerValue]];
                if ([window isKindOfClass:[WineWindow class]] && [window screen] &&
                    ![windows containsObject:window])
                    [windows addObject:window];
            }

            triedWindows = (NSMutableSet*)event->window_got_focus.tried_windows;
            [triedWindows addObject:(WineWindow*)event->window];
            for (window in windows)
            {
                if (![triedWindows containsObject:window] && [window canBecomeKeyWindow])
                {
                    [window makeKeyWindow];
                    break;
                }
            }
            triedWindows = nil;
            [windows release];
        }
    }

    static BOOL EqualInputSource(TISInputSourceRef source1, TISInputSourceRef source2)
    {
        if (!source1 && !source2)
            return TRUE;
        if (!source1 || !source2)
            return FALSE;
        return CFEqual(source1, source2);
    }

    - (void) keyboardSelectionDidChange:(BOOL)force
    {
        TISInputSourceRef inputSource, inputSourceLayout;

        if (!force)
        {
            NSTextInputContext* context = [NSTextInputContext currentInputContext];
            if (!context || ![context client])
                return;
        }

        inputSource = TISCopyCurrentKeyboardInputSource();
        inputSourceLayout = TISCopyCurrentKeyboardLayoutInputSource();
        if (!force && EqualInputSource(inputSource, lastKeyboardInputSource) &&
            EqualInputSource(inputSourceLayout, lastKeyboardLayoutInputSource))
        {
            if (inputSource) CFRelease(inputSource);
            if (inputSourceLayout) CFRelease(inputSourceLayout);
            return;
        }

        if (lastKeyboardInputSource)
            CFRelease(lastKeyboardInputSource);
        lastKeyboardInputSource = inputSource;
        if (lastKeyboardLayoutInputSource)
            CFRelease(lastKeyboardLayoutInputSource);
        lastKeyboardLayoutInputSource = inputSourceLayout;

        if (inputSourceLayout)
        {
            CFDataRef uchr;
            uchr = TISGetInputSourceProperty(inputSourceLayout,
                    kTISPropertyUnicodeKeyLayoutData);
            if (uchr)
            {
                macdrv_event* event;
                WineEventQueue* queue;

                event = macdrv_create_event(KEYBOARD_CHANGED, nil);
                event->keyboard_changed.keyboard_type = self.keyboardType;
                event->keyboard_changed.iso_keyboard = (KBGetLayoutType(self.keyboardType) == kKeyboardISO);
                event->keyboard_changed.uchr = CFDataCreateCopy(NULL, uchr);
                event->keyboard_changed.input_source = (TISInputSourceRef)CFRetain(inputSource);

                if (event->keyboard_changed.uchr)
                {
                    [eventQueuesLock lock];

                    for (queue in eventQueues)
                        [queue postEvent:event];

                    [eventQueuesLock unlock];
                }

                macdrv_release_event(event);
            }
        }
    }

    - (void) keyboardSelectionDidChange
    {
        [self keyboardSelectionDidChange:NO];
    }

    - (void) setKeyboardType:(CGEventSourceKeyboardType)newType
    {
        if (newType != keyboardType)
        {
            keyboardType = newType;
            [self keyboardSelectionDidChange:YES];
        }
    }

    - (void) enabledKeyboardInputSourcesChanged
    {
        macdrv_layout_list_needs_update = TRUE;
    }

    - (CGFloat) primaryScreenHeight
    {
        if (!primaryScreenHeightValid)
        {
            NSArray* screens = [NSScreen screens];
            NSUInteger count = [screens count];
            if (count)
            {
                NSUInteger size;
                CGRect* rect;
                NSScreen* screen;

                primaryScreenHeight = NSHeight([screens[0] frame]);
                primaryScreenHeightValid = TRUE;

                size = count * sizeof(CGRect);
                if (!screenFrameCGRects)
                    screenFrameCGRects = [[NSMutableData alloc] initWithLength:size];
                else
                    [screenFrameCGRects setLength:size];

                rect = [screenFrameCGRects mutableBytes];
                for (screen in screens)
                {
                    CGRect temp = NSRectToCGRect([screen frame]);
                    temp.origin.y = primaryScreenHeight - CGRectGetMaxY(temp);
                    *rect++ = temp;
                }
            }
            else
                return 1280; /* arbitrary value */
        }

        return primaryScreenHeight;
    }

    - (NSPoint) flippedMouseLocation:(NSPoint)point
    {
        /* This relies on the fact that Cocoa's mouse location points are
           actually off by one (precisely because they were flipped from
           Quartz screen coordinates using this same technique). */
        point.y = [self primaryScreenHeight] - point.y;
        return point;
    }

    - (void) flipRect:(NSRect*)rect
    {
        // We don't use -primaryScreenHeight here so there's no chance of having
        // out-of-date cached info.  This method is called infrequently enough
        // that getting the screen height each time is not prohibitively expensive.
        rect->origin.y = NSMaxY([[NSScreen screens][0] frame]) - NSMaxY(*rect);
    }

    - (WineWindow*) frontWineWindow
    {
        NSNumber* windowNumber;
        for (windowNumber in [NSWindow windowNumbersWithOptions:NSWindowNumberListAllSpaces])
        {
            NSWindow* window = [NSApp windowWithWindowNumber:[windowNumber integerValue]];
            if ([window isKindOfClass:[WineWindow class]] && [window screen])
                return (WineWindow*)window;
        }

        return nil;
    }

    - (void) adjustWindowLevels:(BOOL)active
    {
        NSArray* windowNumbers;
        NSMutableArray* wineWindows;
        NSNumber* windowNumber;
        NSUInteger nextFloatingIndex = 0;
        __block NSInteger maxLevel = NSIntegerMin;
        __block NSInteger maxNonfloatingLevel = NSNormalWindowLevel;
        /* Windows with WS_EX_TOPMOST should have a window level higher than the macOS dock */
        __block NSInteger minFloatingLevel = kCGDockWindowLevel + 1;
        __block WineWindow* prev = nil;
        WineWindow* window;

        if ([NSApp isHidden]) return;

        windowNumbers = [NSWindow windowNumbersWithOptions:0];
        wineWindows = [[NSMutableArray alloc] initWithCapacity:[windowNumbers count]];

        // For the most part, we rely on the window server's ordering of the windows
        // to be authoritative.  The one exception is if the "floating" property of
        // one of the windows has been changed, it may be in the wrong level and thus
        // in the order.  This method is what's supposed to fix that up.  So build
        // a list of Wine windows sorted first by floating-ness and then by order
        // as indicated by the window server.
        for (windowNumber in windowNumbers)
        {
            window = (WineWindow*)[NSApp windowWithWindowNumber:[windowNumber integerValue]];
            if ([window isKindOfClass:[WineWindow class]])
            {
                if (window.floating)
                    [wineWindows insertObject:window atIndex:nextFloatingIndex++];
                else
                    [wineWindows addObject:window];
            }
        }

        NSDisableScreenUpdates();

        // Go from back to front so that all windows in front of one which is
        // elevated for full-screen are also elevated.
        [wineWindows enumerateObjectsWithOptions:NSEnumerationReverse
                                      usingBlock:^(id obj, NSUInteger idx, BOOL *stop){
            WineWindow* window = (WineWindow*)obj;
            NSInteger origLevel = [window level];
            NSInteger newLevel = [window minimumLevelForActive:active];

            if (window.floating)
            {
                if (minFloatingLevel <= maxNonfloatingLevel)
                    minFloatingLevel = maxNonfloatingLevel + 1;
                if (newLevel < minFloatingLevel)
                    newLevel = minFloatingLevel;
            }

            if (newLevel < maxLevel)
                newLevel = maxLevel;
            else
                maxLevel = newLevel;

            if (!window.floating && maxNonfloatingLevel < newLevel)
                maxNonfloatingLevel = newLevel;

            if (newLevel != origLevel)
            {
                [window setLevel:newLevel];

                if (origLevel < newLevel)
                {
                    // If we increased the level, the window should be toward the
                    // back of its new level (but still ahead of the previous
                    // windows we did this to).
                    if (prev)
                        [window orderWindow:NSWindowAbove relativeTo:[prev windowNumber]];
                    else
                        [window orderBack:nil];
                }
                else
                {
                    // If we decreased the level, we want the window at the top
                    // of its new level. -setLevel: is documented to do that on
                    // its own, but that's buggy on Ventura. Since we're looping
                    // back-to-front here, -orderFront: will do the right thing.
                    [window orderFront:nil];
                }
            }

            prev = window;
        }];

        NSEnableScreenUpdates();

        [wineWindows release];

        // The above took care of the visible windows on the current space.  That
        // leaves windows on other spaces, minimized windows, and windows which
        // are not ordered in.  We want to leave windows on other spaces alone
        // so the space remains just as they left it (when viewed in Exposé or
        // Mission Control, for example).  We'll adjust the window levels again
        // after we switch to another space, anyway.  Windows which aren't
        // ordered in will be handled when we order them in.  Minimized windows
        // on the current space should be set to the level they would have gotten
        // if they were at the front of the windows with the same floating-ness,
        // because that's where they'll go if/when they are unminimized.  Again,
        // for good measure we'll adjust window levels again when a window is
        // unminimized, too.
        for (window in [NSApp windows])
        {
            if ([window isKindOfClass:[WineWindow class]] && [window isMiniaturized] &&
                [window isOnActiveSpace])
            {
                NSInteger origLevel = [window level];
                NSInteger newLevel = [window minimumLevelForActive:YES];
                NSInteger maxLevelForType = window.floating ? maxLevel : maxNonfloatingLevel;

                if (newLevel < maxLevelForType)
                    newLevel = maxLevelForType;

                if (newLevel != origLevel)
                    [window setLevel:newLevel];
            }
        }
    }

    - (void) adjustWindowLevels
    {
        [self adjustWindowLevels:[NSApp isActive]];
    }

    - (void) updateFullscreenWindows
    {
        if (capture_displays_for_fullscreen && [NSApp isActive])
        {
            BOOL anyFullscreen = FALSE;
            NSNumber* windowNumber;
            for (windowNumber in [NSWindow windowNumbersWithOptions:0])
            {
                WineWindow* window = (WineWindow*)[NSApp windowWithWindowNumber:[windowNumber integerValue]];
                if ([window isKindOfClass:[WineWindow class]] && window.fullscreen)
                {
                    anyFullscreen = TRUE;
                    break;
                }
            }

            if (anyFullscreen)
            {
                if ([self areDisplaysCaptured] || CGCaptureAllDisplays() == CGDisplayNoErr)
                    displaysCapturedForFullscreen = TRUE;
            }
            else if (displaysCapturedForFullscreen)
            {
                if ([originalDisplayModes count] || CGReleaseAllDisplays() == CGDisplayNoErr)
                    displaysCapturedForFullscreen = FALSE;
            }
        }

        /* PROTON_NO_LEVEL_ELEVATION suppresses the captured-display /
         * NSStatusWindowLevel elevation that would otherwise hide the
         * menubar via window level. Compensate by toggling
         * +[NSMenu setMenuBarVisible:] so fullscreen wine windows
         * appear edge-to-edge. setMenuBarVisible: does NOT alter
         * NSScreen.visibleFrame (unlike setPresentationOptions), so
         * in-flight IOSurfaces in the compositor lane are not
         * invalidated. See patch header for the Eternal regression
         * that motivated the API swap. */
        [self updateMenuBarHiding];
    }

    - (void) updateMenuBarHiding
    {
        static int gate_cached = -1;
        BOOL anyFullscreenActive = FALSE;
        BOOL desiredVisible;

        if (gate_cached < 0)
        {
            const char *v = getenv("PROTON_NO_LEVEL_ELEVATION");
            gate_cached = (v && *v && *v != '0') ? 1 : 0;
        }
        if (!gate_cached) return;

        /* Per-appid safety belt. Even with 2s dispatch_after defer
         * (2026-05-23), DOOM Eternal (782330) main menu still doesn't
         * render — the WindowServer compositor reconfigure breaks
         * the MAILBOX swapchain regardless of timing within ~seconds.
         * Keep the skip until a deeper fix is found. */
        if (proton_menubar_hide_skip_appid() && !proton_force_menubar_hide()) return;
        if (proton_force_menubar_hide())
            fprintf(stderr, "winemac: [FORCE-MENUBAR-HIDE] bypassing per-appid skip\n");

        if ([NSApp isActive])
        {
            for (NSNumber* windowNumber in [NSWindow windowNumbersWithOptions:0])
            {
                WineWindow* window = (WineWindow*)[NSApp windowWithWindowNumber:[windowNumber integerValue]];
                if ([window isKindOfClass:[WineWindow class]] && window.fullscreen)
                {
                    anyFullscreenActive = TRUE;
                    break;
                }
            }
        }

        /* Deployment verification marker. The literal "[PROTON-MENUBAR-HIDE]"
         * is unique enough to survive into `strings winemac.so` output, which
         * lets us confirm a built binary actually picked up this overlay
         * (ObjC selector names do not reliably show up in strings). */
        fprintf(stderr, "winemac: [PROTON-MENUBAR-HIDE] anyFullscreen=%d\n",
                (int)anyFullscreenActive);

        desiredVisible = anyFullscreenActive ? NO : YES;

        if (desiredVisible)
        {
            /* SHOW: restore menu bar promptly when the wine window
             * is no longer fullscreen-active. */
            if (![NSMenu menuBarVisible])
                [NSMenu setMenuBarVisible:YES];
        }
        else
        {
            /* HIDE: defer by 2s. setMenuBarVisible: shares the WindowServer
             * write path with setPresentationOptions: (per SDL #14265 and
             * Mozilla bug 1172664: both route through SetSystemUIMode).
             * The resulting compositor reconfigure drops the in-flight
             * Vulkan drawable for engines using VK_PRESENT_MODE_MAILBOX_KHR
             * with tight pipelining — confirmed black-screens DOOM Eternal
             * main menu on 2026-05-23. Deferring lets the swapchain reach
             * steady state before the toggle. Re-check state at fire time
             * because the deferred block may execute after the app has lost
             * focus or the fullscreen window has changed. */
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC),
                           dispatch_get_main_queue(), ^{
                BOOL stillNeedsHide = FALSE;
                if ([NSApp isActive])
                {
                    for (NSNumber* wn in [NSWindow windowNumbersWithOptions:0])
                    {
                        WineWindow* w = (WineWindow*)[NSApp windowWithWindowNumber:[wn integerValue]];
                        if ([w isKindOfClass:[WineWindow class]] && w.fullscreen)
                        {
                            stillNeedsHide = TRUE;
                            break;
                        }
                    }
                }
                if (stillNeedsHide && [NSMenu menuBarVisible])
                {
                    fprintf(stderr, "winemac: [PROTON-MENUBAR-HIDE-DEFERRED] firing hide after settle\n");
                    [NSMenu setMenuBarVisible:NO];
                }
            });
        }
    }

    - (void) activeSpaceDidChange
    {
        [self updateFullscreenWindows];
        [self adjustWindowLevels];
    }

    - (void) sendDisplaysChanged:(BOOL)activating
    {
        macdrv_event* event;
        WineEventQueue* queue;

        event = macdrv_create_event(DISPLAYS_CHANGED, nil);
        event->displays_changed.activating = activating;

        [eventQueuesLock lock];

        // If we're activating, then we just need one of our threads to get the
        // event, so it can send it directly to the desktop window.  Otherwise,
        // we need all of the threads to get it because we don't know which owns
        // the desktop window and only that one will do anything with it.
        if (activating) event->deliver = 1;

        for (queue in eventQueues)
            [queue postEvent:event];
        [eventQueuesLock unlock];

        macdrv_release_event(event);
    }

    // We can compare two modes directly using CFEqual, but that may require that
    // they are identical to a level that we don't need.  In particular, when the
    // OS switches between the integrated and discrete GPUs, the set of display
    // modes can change in subtle ways.  We're interested in whether two modes
    // match in their most salient features, even if they aren't identical.
    - (BOOL) mode:(CGDisplayModeRef)mode1 matchesMode:(CGDisplayModeRef)mode2
    {
        NSString *encoding1, *encoding2;
        uint32_t ioflags1, ioflags2, different;
        double refresh1, refresh2;

        if (CGDisplayModeGetWidth(mode1) != CGDisplayModeGetWidth(mode2)) return FALSE;
        if (CGDisplayModeGetHeight(mode1) != CGDisplayModeGetHeight(mode2)) return FALSE;
        if (CGDisplayModeGetPixelWidth(mode1) != CGDisplayModeGetPixelWidth(mode2)) return FALSE;
        if (CGDisplayModeGetPixelHeight(mode1) != CGDisplayModeGetPixelHeight(mode2)) return FALSE;

        encoding1 = [(NSString*)CGDisplayModeCopyPixelEncoding(mode1) autorelease];
        encoding2 = [(NSString*)CGDisplayModeCopyPixelEncoding(mode2) autorelease];
        if (![encoding1 isEqualToString:encoding2]) return FALSE;

        ioflags1 = CGDisplayModeGetIOFlags(mode1);
        ioflags2 = CGDisplayModeGetIOFlags(mode2);
        different = ioflags1 ^ ioflags2;
        if (different & (kDisplayModeValidFlag | kDisplayModeSafeFlag | kDisplayModeStretchedFlag |
                         kDisplayModeInterlacedFlag | kDisplayModeTelevisionFlag))
            return FALSE;

        refresh1 = CGDisplayModeGetRefreshRate(mode1);
        if (refresh1 == 0) refresh1 = 60;
        refresh2 = CGDisplayModeGetRefreshRate(mode2);
        if (refresh2 == 0) refresh2 = 60;
        if (fabs(refresh1 - refresh2) > 0.1) return FALSE;

        return TRUE;
    }

    - (NSArray*)modesMatchingMode:(CGDisplayModeRef)mode forDisplay:(CGDirectDisplayID)displayID
    {
        NSMutableArray* ret = [NSMutableArray array];
        NSDictionary* options = @{ (NSString*)kCGDisplayShowDuplicateLowResolutionModes: @YES };

        NSArray *modes = [(NSArray*)CGDisplayCopyAllDisplayModes(displayID, (CFDictionaryRef)options) autorelease];
        for (id candidateModeObject in modes)
        {
            CGDisplayModeRef candidateMode = (CGDisplayModeRef)candidateModeObject;
            if ([self mode:candidateMode matchesMode:mode])
                [ret addObject:candidateModeObject];
        }
        return ret;
    }

    - (BOOL) setMode:(CGDisplayModeRef)mode forDisplay:(CGDirectDisplayID)displayID
    {
        BOOL ret = FALSE;
        NSNumber* displayIDKey = [NSNumber numberWithUnsignedInt:displayID];
        CGDisplayModeRef originalMode;

        originalMode = (CGDisplayModeRef)originalDisplayModes[displayIDKey];

        if (originalMode && [self mode:mode matchesMode:originalMode])
        {
            if ([originalDisplayModes count] == 1) // If this is the last changed display, do a blanket reset
            {
                CGRestorePermanentDisplayConfiguration();
                if (!displaysCapturedForFullscreen)
                    CGReleaseAllDisplays();
                [originalDisplayModes removeAllObjects];
                ret = TRUE;
            }
            else // ... otherwise, try to restore just the one display
            {
                for (id modeObject in [self modesMatchingMode:mode forDisplay:displayID])
                {
                    mode = (CGDisplayModeRef)modeObject;
                    if (CGDisplaySetDisplayMode(displayID, mode, NULL) == CGDisplayNoErr)
                    {
                        [originalDisplayModes removeObjectForKey:displayIDKey];
                        ret = TRUE;
                        break;
                    }
                }
            }
        }
        else
        {
            CGDisplayModeRef currentMode;
            NSArray* modes;

            currentMode = CGDisplayModeRetain((CGDisplayModeRef)latentDisplayModes[displayIDKey]);
            if (!currentMode)
                currentMode = CGDisplayCopyDisplayMode(displayID);
            if (!currentMode) // Invalid display ID
                return FALSE;

            if ([self mode:mode matchesMode:currentMode]) // Already there!
            {
                CGDisplayModeRelease(currentMode);
                return TRUE;
            }

            CGDisplayModeRelease(currentMode);
            currentMode = NULL;

            modes = [self modesMatchingMode:mode forDisplay:displayID];
            if (!modes.count)
                return FALSE;

            [self transformProcessToForeground:YES];

            BOOL active = [NSApp isActive];

            if ([originalDisplayModes count] || displaysCapturedForFullscreen ||
                !active || CGCaptureAllDisplays() == CGDisplayNoErr)
            {
                if (active)
                {
                    // If we get here, we have the displays captured.  If we don't
                    // know the original mode of the display, the current mode must
                    // be the original.  We should re-query the current mode since
                    // another process could have changed it between when we last
                    // checked and when we captured the displays.
                    if (!originalMode)
                        originalMode = currentMode = CGDisplayCopyDisplayMode(displayID);

                    if (originalMode)
                    {
                        for (id modeObject in modes)
                        {
                            mode = (CGDisplayModeRef)modeObject;
                            if (CGDisplaySetDisplayMode(displayID, mode, NULL) == CGDisplayNoErr)
                            {
                                ret = TRUE;
                                break;
                            }
                        }
                    }
                    if (ret && !(currentMode && [self mode:mode matchesMode:currentMode]))
                        [originalDisplayModes setObject:(id)originalMode forKey:displayIDKey];
                    else if (![originalDisplayModes count])
                    {
                        CGRestorePermanentDisplayConfiguration();
                        if (!displaysCapturedForFullscreen)
                            CGReleaseAllDisplays();
                    }

                    if (currentMode)
                        CGDisplayModeRelease(currentMode);
                }
                else
                {
                    [latentDisplayModes setObject:(id)mode forKey:displayIDKey];
                    ret = TRUE;
                }
            }
        }

        if (ret)
            [self adjustWindowLevels];

        return ret;
    }

    - (BOOL) areDisplaysCaptured
    {
        return ([originalDisplayModes count] > 0 || displaysCapturedForFullscreen);
    }

    - (void) updateCursor:(BOOL)force
    {
        if (force || lastTargetWindow)
        {
            if (clientWantsCursorHidden && !cursorHidden)
            {
                [NSCursor hide];
                cursorHidden = TRUE;
            }

            if (!cursorIsCurrent)
            {
                [cursor set];
                cursorIsCurrent = TRUE;
            }

            if (!clientWantsCursorHidden && cursorHidden)
            {
                [NSCursor unhide];
                cursorHidden = FALSE;
            }
        }
        else
        {
            if (cursorIsCurrent)
            {
                [[NSCursor arrowCursor] set];
                cursorIsCurrent = FALSE;
            }
            if (cursorHidden)
            {
                [NSCursor unhide];
                cursorHidden = FALSE;
            }
        }
    }

    - (void) hideCursor
    {
        if (!clientWantsCursorHidden)
        {
            clientWantsCursorHidden = TRUE;
            [self updateCursor:TRUE];
        }
    }

    - (void) unhideCursor
    {
        if (clientWantsCursorHidden)
        {
            clientWantsCursorHidden = FALSE;
            [self updateCursor:FALSE];
        }
    }

    - (void) setCursor:(NSCursor*)newCursor
    {
        if (newCursor != cursor)
        {
            [cursor release];
            cursor = [newCursor retain];
            cursorIsCurrent = FALSE;
            [self updateCursor:FALSE];
        }
    }

    - (void) setCursor
    {
        NSDictionary* frame = cursorFrames[cursorFrame];
        CGImageRef cgimage = (CGImageRef)frame[@"image"];
        CGSize size = CGSizeMake(CGImageGetWidth(cgimage), CGImageGetHeight(cgimage));
        NSImage* image = [[NSImage alloc] initWithCGImage:cgimage size:NSSizeFromCGSize(cgsize_mac_from_win(size))];
        CFDictionaryRef hotSpotDict = (CFDictionaryRef)frame[@"hotSpot"];
        CGPoint hotSpot;

        if (!CGPointMakeWithDictionaryRepresentation(hotSpotDict, &hotSpot))
            hotSpot = CGPointZero;
        hotSpot = cgpoint_mac_from_win(hotSpot);
        self.cursor = [[[NSCursor alloc] initWithImage:image hotSpot:NSPointFromCGPoint(hotSpot)] autorelease];
        [image release];
        [self unhideCursor];
    }

    - (void) nextCursorFrame:(NSTimer*)theTimer
    {
        NSDictionary* frame;
        NSTimeInterval duration;
        NSDate* date;

        cursorFrame++;
        if (cursorFrame >= [cursorFrames count])
            cursorFrame = 0;
        [self setCursor];

        frame = cursorFrames[cursorFrame];
        duration = [frame[@"duration"] doubleValue];
        date = [[theTimer fireDate] dateByAddingTimeInterval:duration];
        [cursorTimer setFireDate:date];
    }

    - (void) setCursorWithFrames:(NSArray*)frames
    {
        if (self.cursorFrames == frames || [self.cursorFrames isEqualToArray:frames])
            return;

        self.cursorFrames = frames;
        cursorFrame = 0;
        [cursorTimer invalidate];
        self.cursorTimer = nil;

        if ([frames count])
        {
            if ([frames count] > 1)
            {
                NSDictionary* frame = frames[0];
                NSTimeInterval duration = [frame[@"duration"] doubleValue];
                NSDate* date = [NSDate dateWithTimeIntervalSinceNow:duration];
                self.cursorTimer = [[[NSTimer alloc] initWithFireDate:date
                                                             interval:1000000
                                                               target:self
                                                             selector:@selector(nextCursorFrame:)
                                                             userInfo:nil
                                                              repeats:YES] autorelease];
                [[NSRunLoop currentRunLoop] addTimer:cursorTimer forMode:NSRunLoopCommonModes];
            }

            [self setCursor];
        }
    }

    - (void) setApplicationIconFromCGImageArray:(NSArray*)images
    {
        NSImage* nsimage = nil;

        if ([images count])
        {
            NSSize bestSize = NSZeroSize;
            id image;

            nsimage = [[[NSImage alloc] initWithSize:NSZeroSize] autorelease];

            for (image in images)
            {
                CGImageRef cgimage = (CGImageRef)image;
                NSBitmapImageRep* imageRep = [[NSBitmapImageRep alloc] initWithCGImage:cgimage];
                if (imageRep)
                {
                    NSSize size = [imageRep size];

                    [nsimage addRepresentation:imageRep];
                    [imageRep release];

                    if (MIN(size.width, size.height) > MIN(bestSize.width, bestSize.height))
                        bestSize = size;
                }
            }

            if ([[nsimage representations] count] && bestSize.width && bestSize.height)
                [nsimage setSize:bestSize];
            else
                nsimage = nil;
        }

        self.applicationIcon = nsimage;
    }

    - (void) handleCommandTab
    {
        if ([NSApp isActive])
        {
            NSRunningApplication* thisApp = [NSRunningApplication currentApplication];
            NSRunningApplication* app;
            NSRunningApplication* otherValidApp = nil;

            if ([originalDisplayModes count] || displaysCapturedForFullscreen)
            {
                NSNumber* displayID;
                for (displayID in originalDisplayModes)
                {
                    CGDisplayModeRef mode = CGDisplayCopyDisplayMode([displayID unsignedIntValue]);
                    [latentDisplayModes setObject:(id)mode forKey:displayID];
                    CGDisplayModeRelease(mode);
                }

                CGRestorePermanentDisplayConfiguration();
                CGReleaseAllDisplays();
                [originalDisplayModes removeAllObjects];
                displaysCapturedForFullscreen = FALSE;
            }

            for (app in [[NSWorkspace sharedWorkspace] runningApplications])
            {
                if (![app isEqual:thisApp] && !app.terminated &&
                    app.activationPolicy == NSApplicationActivationPolicyRegular)
                {
                    if (!app.hidden)
                    {
                        // There's another visible app.  Just hide ourselves and let
                        // the system activate the other app.
                        [NSApp hide:self];
                        return;
                    }

                    if (!otherValidApp)
                        otherValidApp = app;
                }
            }

            // Didn't find a visible GUI app.  Try the Finder or, if that's not
            // running, the first hidden GUI app.  If even that doesn't work, we
            // just fail to switch and remain the active app.
            app = [[NSRunningApplication runningApplicationsWithBundleIdentifier:@"com.apple.finder"] lastObject];
            if (!app) app = otherValidApp;
            [app unhide];
            [app activateWithOptions:0];
        }
    }

    - (BOOL) setCursorPosition:(CGPoint)pos
    {
        BOOL ret;

        if ([windowsBeingDragged count])
            ret = FALSE;
        else if (self.clippingCursor && [clipCursorHandler respondsToSelector:@selector(setCursorPosition:)])
            ret = [clipCursorHandler setCursorPosition:pos];
        else
        {
            if (self.clippingCursor)
                [clipCursorHandler clipCursorLocation:&pos];

            // Annoyingly, CGWarpMouseCursorPosition() effectively disassociates
            // the mouse from the cursor position for 0.25 seconds.  This means
            // that mouse movement during that interval doesn't move the cursor
            // and events carry a constant location (the warped-to position)
            // even though they have delta values.  For apps which warp the
            // cursor frequently (like after every mouse move), this makes
            // cursor movement horribly laggy and jerky, as only a fraction of
            // mouse move events have any effect.
            //
            // On some versions of OS X, it's sufficient to forcibly reassociate
            // the mouse and cursor position.  On others, it's necessary to set
            // the local events suppression interval to 0 for the warp.  That's
            // deprecated, but I'm not aware of any other way.  For good
            // measure, we do both.
            CGSetLocalEventsSuppressionInterval(0);
            ret = (CGWarpMouseCursorPosition(pos) == kCGErrorSuccess);
            CGSetLocalEventsSuppressionInterval(0.25);
            if (ret)
            {
                lastSetCursorPositionTime = [[NSProcessInfo processInfo] systemUptime];

                /* PROTON_FORCE_FPS_MOUSE: when disassociation is engaged
                 * (FPS mode on), the game is calling SetCursorPos every
                 * frame to recenter the cursor for raw input. Re-associating
                 * here on every warp undoes the disassociation and causes
                 * the cursor to track mouse → motion deltas get trampled
                 * by the next recenter warp. Keep disassociation sticky. */
                if (!macdrv_mouse_disassociated)
                    CGAssociateMouseAndMouseCursorPosition(true);
            }
        }

        if (ret)
        {
            WineEventQueue* queue;

            // Discard all pending mouse move events.
            [eventQueuesLock lock];
            for (queue in eventQueues)
            {
                [queue discardEventsMatchingMask:event_mask_for_type(MOUSE_MOVED_RELATIVE) |
                                                 event_mask_for_type(MOUSE_MOVED_ABSOLUTE)
                                       forWindow:nil];
                [queue resetMouseEventPositions:pos];
            }
            [eventQueuesLock unlock];
        }

        return ret;
    }

    - (void) updateWindowsForCursorClipping
    {
        WineWindow* window;
        for (window in [NSApp windows])
        {
            if ([window isKindOfClass:[WineWindow class]])
                [window updateForCursorClipping];
        }
    }

    - (BOOL) startClippingCursor:(CGRect)rect
    {
        if (!clipCursorHandler) {
            if (use_confinement_cursor_clipping && [WineConfinementClipCursorHandler isAvailable])
                clipCursorHandler = [[WineConfinementClipCursorHandler alloc] init];
            else
                clipCursorHandler = [[WineEventTapClipCursorHandler alloc] init];
        }

        if (self.clippingCursor && CGRectEqualToRect(rect, clipCursorHandler.cursorClipRect))
            return TRUE;

        if (![clipCursorHandler startClippingCursor:rect])
            return FALSE;

        [self setCursorPosition:NSPointToCGPoint([self flippedMouseLocation:[NSEvent mouseLocation]])];

        [self updateWindowsForCursorClipping];

        return TRUE;
    }

    - (BOOL) stopClippingCursor
    {
        if (!self.clippingCursor)
            return TRUE;

        if (![clipCursorHandler stopClippingCursor])
            return FALSE;

        lastSetCursorPositionTime = [[NSProcessInfo processInfo] systemUptime];

        [self updateWindowsForCursorClipping];

        return TRUE;
    }

    - (BOOL) clippingCursor
    {
        return clipCursorHandler.clippingCursor;
    }

    - (BOOL) isKeyPressed:(uint16_t)keyCode
    {
        int bits = sizeof(pressedKeyCodes[0]) * 8;
        int index = keyCode / bits;
        uint32_t mask = 1 << (keyCode % bits);
        return (pressedKeyCodes[index] & mask) != 0;
    }

    - (void) noteKey:(uint16_t)keyCode pressed:(BOOL)pressed
    {
        int bits = sizeof(pressedKeyCodes[0]) * 8;
        int index = keyCode / bits;
        uint32_t mask = 1 << (keyCode % bits);
        if (pressed)
            pressedKeyCodes[index] |= mask;
        else
            pressedKeyCodes[index] &= ~mask;
    }

    - (void) window:(WineWindow*)window isBeingDragged:(BOOL)dragged
    {
        if (dragged)
            [windowsBeingDragged addObject:window];
        else
            [windowsBeingDragged removeObject:window];
    }

    - (void) windowWillOrderOut:(WineWindow*)window
    {
        if ([windowsBeingDragged containsObject:window])
        {
            [self window:window isBeingDragged:NO];

            macdrv_event* event = macdrv_create_event(WINDOW_DRAG_END, window);
            [window.queue postEvent:event];
            macdrv_release_event(event);
        }
    }

    - (BOOL) isAnyWineWindowVisible
    {
        for (WineWindow* w in [NSApp windows])
        {
            if ([w isKindOfClass:[WineWindow class]] && ![w isMiniaturized] && [w isVisible] && [w presentsVisibleContent])
                return YES;
        }

        return NO;
    }

    - (void) handleWindowDrag:(WineWindow*)window begin:(BOOL)begin
    {
        macdrv_event* event;
        int eventType;

        if (begin)
        {
            [windowsBeingDragged addObject:window];
            eventType = WINDOW_DRAG_BEGIN;
        }
        else
        {
            [windowsBeingDragged removeObject:window];
            eventType = WINDOW_DRAG_END;
        }

        event = macdrv_create_event(eventType, window);
        if (eventType == WINDOW_DRAG_BEGIN)
            event->window_drag_begin.no_activate = [NSEvent wine_commandKeyDown];
        [window.queue postEvent:event];
        macdrv_release_event(event);
    }

    - (void) handleMouseMove:(NSEvent*)anEvent
    {
        WineWindow* targetWindow;
        BOOL drag = [anEvent type] != NSEventTypeMouseMoved;

        if ([windowsBeingDragged count])
            targetWindow = nil;
        else if (mouseCaptureWindow)
            targetWindow = mouseCaptureWindow;
        else if (drag)
            targetWindow = (WineWindow*)[anEvent window];
        else
        {
            /* Because of the way -[NSWindow setAcceptsMouseMovedEvents:] works, the
               event indicates its window is the main window, even if the cursor is
               over a different window.  Find the actual WineWindow that is under the
               cursor and post the event as being for that window. */
            CGPoint cgpoint = CGEventGetLocation([anEvent CGEvent]);
            NSPoint point = [self flippedMouseLocation:NSPointFromCGPoint(cgpoint)];
            NSInteger windowUnderNumber;

            windowUnderNumber = [NSWindow windowNumberAtPoint:point
                                  belowWindowWithWindowNumber:0];
            targetWindow = (WineWindow*)[NSApp windowWithWindowNumber:windowUnderNumber];
            if (!NSMouseInRect(point, [targetWindow contentRectForFrameRect:[targetWindow frame]], NO))
                targetWindow = nil;
        }

        if ([targetWindow isKindOfClass:[WineWindow class]])
        {
            CGPoint point = CGEventGetLocation([anEvent CGEvent]);
            macdrv_event* event;
            BOOL absolute;

            // If we recently warped the cursor (other than in our cursor-clipping
            // event tap), discard mouse move events until we see an event which is
            // later than that time.
            //
            // 2026-04-26 macOS-port mod: trackpad events arrive in dense clusters
            // with timestamps within ~10ms of each other. Skyrim/DS3 warp the
            // cursor every frame for relative-motion capture; the previous "<=
            // warp time" discard swallowed almost all trackpad input. Use a
            // tighter 16ms (~1 frame) discard window instead - keeps the warp's
            // own synthetic events filtered while letting genuine pre-warp
            // trackpad samples through.
            //
            // Also: track whether we've seen a SetCursorPos in the last 500ms.
            // If yes, the app is doing FPS-style cursor recentering; force
            // RELATIVE mouse mode so the game's mouse-look reads delta values
            // instead of (always-the-same after warp) absolute positions.
            BOOL recentWarp = NO;
            if (lastSetCursorPositionTime)
            {
                NSTimeInterval evt_time = [anEvent timestamp];
                if (evt_time + 0.016 <= lastSetCursorPositionTime)
                    return;

                lastSetCursorPositionTime = 0;
                /* Don't force absolute on the first post-warp event - that
                 * defeats relative-mode tracking for FPS games. Just clear
                 * the discard window and let the regular interior/boundary
                 * logic decide. */
                recentWarp = YES;
            }
            /* FPS-mode trigger: app called ClipCursor OR SetCapture OR is in
             * fullscreen with cursor hidden. Any of these suggests mouse-look.
             * Force RELATIVE motion + disassociate Mac cursor so trackpad
             * deltas go directly to the game. */
            /* [FPS-CURSOR] The game hid the cursor (SetCursor NULL) while a target
             * window is focused — the universal signal for in-game mouse-look
             * (FPS / 3rd-person camera). MENUS show the cursor, so this trigger
             * auto-DISENGAGES there, giving relative motion in-game and an absolute
             * cursor in menus WITHOUT PROTON_FORCE_FPS_MOUSE (which is always-on and
             * kills the menu cursor). This is the cursor-state the [fullscreen]
             * heuristic below was a poor proxy for (fullscreen can't tell in-game
             * from a fullscreen menu), and it fixes the laggy-default-vs-dead-menu
             * split on raw-input titles (DOOM, KCD2). Opt out via PROTON_NO_FPS_MOUSE
             * for cursor-driven titles that hide the cursor in menus (Detroit). */
            /* A capture flagged GUI_INMOVESIZE is Wine's OWN window drag loop
             * (defwnd.c captures for the duration of a caption drag), NOT the app
             * asking for mouse-look. Counting it disassociated the cursor mid-drag:
             * the pointer froze at the grab point while the window followed stale
             * deltas, then snapped back on release. Confirmed 2026-09-06. */
            BOOL fpsModeActive = self.clippingCursor
                              || (self.mouseCaptureWindow != nil
                                  && self.mouseCaptureWindow == targetWindow
                                  && !self.mouseCaptureIsMoveSize)
                              || (clientWantsCursorHidden && targetWindow != nil)
                              || (cursor_clipping_locks_windows
                                  && [(WineWindow*)targetWindow respondsToSelector:@selector(fullscreen)]
                                  && [(WineWindow*)targetWindow fullscreen]);
            /* PROTON_FORCE_FPS_MOUSE=1: force fpsModeActive on any
             * target window, ignoring the [fullscreen] gate. Fix for
             * titles (DOOM Eternal) whose RIDEV_NOLEGACY raw input
             * path needs cursor disassociation but whose window state
             * doesn't match Wine's heuristic (borderless-sized-to-
             * screen vs Wine's [fullscreen] property). */
            static int force_cached = -1;
            if (force_cached < 0) {
                const char *v = getenv("PROTON_FORCE_FPS_MOUSE");
                force_cached = (v && v[0] && !(v[0] == '0' && v[1] == '\0')) ? 1 : 0;
            }
            if (force_cached && targetWindow)
                fpsModeActive = YES;
            /* PROTON_NO_FPS_MOUSE=1: never enter FPS/relative mouse mode — keep
             * the Mac cursor ASSOCIATED so the absolute OS cursor position keeps
             * updating. Inverse of PROTON_FORCE_FPS_MOUSE. Recipes set this for
             * narrative / cursor-driven titles (Detroit: Become Human) that
             * ClipCursor in their menus: Wine would otherwise disassociate the
             * mouse into relative mouse-look, freezing the absolute cursor so
             * menu buttons can't be moused (clicks land, the cursor just can't
             * move). Placed after the force override so suppression wins. */
            static int no_fps_cached = -1;
            if (no_fps_cached < 0) {
                const char *v = getenv("PROTON_NO_FPS_MOUSE");
                no_fps_cached = (v && v[0] && !(v[0] == '0' && v[1] == '\0')) ? 1 : 0;
            }
            if (no_fps_cached)
                fpsModeActive = NO;
            if (fpsModeActive != macdrv_mouse_disassociated) {
                CGAssociateMouseAndMouseCursorPosition(!fpsModeActive);
                macdrv_mouse_disassociated = fpsModeActive;
                fprintf(stderr, "winemac:mouse FPS mode = %d (clippingCursor)\n", fpsModeActive);
            }

            if (forceNextMouseMoveAbsolute || targetWindow != lastTargetWindow)
            {
                absolute = TRUE;
                forceNextMouseMoveAbsolute = FALSE;
            }
            else if (fpsModeActive)
            {
                /* FPS-mode override: app is recentering cursor every frame,
                 * so it wants relative motion deltas. Skip the
                 * "in interior of range = send absolute" heuristic. */
                absolute = FALSE;
            }
            else if (force_cached)
            {
                /* PROTON_FORCE_FPS_MOUSE: opt-in to relative motion deltas
                 * regardless of fullscreen detection or fpsModeActive
                 * heuristic. Recipes set this for titles (DOOM Eternal)
                 * whose RIDEV_NOLEGACY raw-input path expects relative
                 * deltas, and whose window state may not match Wine's
                 * fpsModeActive triggers. */
                absolute = FALSE;
            }
            else
            {
                // Send absolute move events if the cursor is in the interior of
                // its range.  Only send relative moves if the cursor is pinned to
                // the boundaries of where it can go.  We compute the position
                // that's one additional point in the direction of movement.  If
                // that is outside of the clipping rect or desktop region (the
                // union of the screen frames), then we figure the cursor would
                // have moved outside if it could but it was pinned.
                CGPoint computedPoint = point;
                CGFloat deltaX = [anEvent deltaX];
                CGFloat deltaY = [anEvent deltaY];

                if (deltaX > 0.001)
                    computedPoint.x++;
                else if (deltaX < -0.001)
                    computedPoint.x--;

                if (deltaY > 0.001)
                    computedPoint.y++;
                else if (deltaY < -0.001)
                    computedPoint.y--;

                // Assume cursor is pinned for now
                absolute = FALSE;
                if (!self.clippingCursor || CGRectContainsPoint(clipCursorHandler.cursorClipRect, computedPoint))
                {
                    const CGRect* rects;
                    NSUInteger count, i;

                    // Caches screenFrameCGRects if necessary
                    [self primaryScreenHeight];

                    rects = [screenFrameCGRects bytes];
                    count = [screenFrameCGRects length] / sizeof(rects[0]);

                    for (i = 0; i < count; i++)
                    {
                        if (CGRectContainsPoint(rects[i], computedPoint))
                        {
                            absolute = TRUE;
                            break;
                        }
                    }
                }
            }

            if (absolute)
            {
                if (self.clippingCursor)
                    [clipCursorHandler clipCursorLocation:&point];
                point = cgpoint_win_from_mac(point);

                event = macdrv_create_event(MOUSE_MOVED_ABSOLUTE, targetWindow);
                event->mouse_moved.x = floor(point.x);
                event->mouse_moved.y = floor(point.y);

                mouseMoveDeltaX = 0;
                mouseMoveDeltaY = 0;
            }
            else
            {
                double scale = retina_on ? 2 : 1;
                /* Scale and cap relative deltas. The macOS trackpad/mouse driver
                   pre-applies a pointer acceleration curve to -[NSEvent deltaX/Y].
                   Games that run their own raw-input accel (Source engine, etc.)
                   end up double-accelerated, producing "look at ceiling, spin fast".
                   MouseRelativeMotionScale lets the user dampen; MouseRelativeMotionCap
                   clamps per-axis magnitude in post-scale pixels (0 = disabled). */
                double dx = [anEvent deltaX] * mouse_relative_motion_scale;
                double dy = [anEvent deltaY] * mouse_relative_motion_scale;
                if (mouse_relative_motion_cap > 0.0)
                {
                    if (dx >  mouse_relative_motion_cap) dx =  mouse_relative_motion_cap;
                    if (dx < -mouse_relative_motion_cap) dx = -mouse_relative_motion_cap;
                    if (dy >  mouse_relative_motion_cap) dy =  mouse_relative_motion_cap;
                    if (dy < -mouse_relative_motion_cap) dy = -mouse_relative_motion_cap;
                }

                /* Add event delta to accumulated delta error */
                /* deltaY is already flipped */
                mouseMoveDeltaX += dx;
                mouseMoveDeltaY += dy;

                event = macdrv_create_event(MOUSE_MOVED_RELATIVE, targetWindow);
                event->mouse_moved.x = mouseMoveDeltaX * scale;
                event->mouse_moved.y = mouseMoveDeltaY * scale;

                /* Keep the remainder after integer truncation. */
                mouseMoveDeltaX -= event->mouse_moved.x / scale;
                mouseMoveDeltaY -= event->mouse_moved.y / scale;
            }

            if (event->type == MOUSE_MOVED_ABSOLUTE || event->mouse_moved.x || event->mouse_moved.y)
            {
                event->mouse_moved.time_ms = [self ticksForEventTime:[anEvent timestamp]];
                event->mouse_moved.drag = drag;

                [targetWindow.queue postEvent:event];
            }

            macdrv_release_event(event);

            lastTargetWindow = targetWindow;
        }
        else
            lastTargetWindow = nil;

        [self updateCursor:FALSE];
    }

    - (void) handleMouseButton:(NSEvent*)theEvent
    {
        WineWindow* window = (WineWindow*)[theEvent window];
        NSEventType type = [theEvent type];
        WineWindow* windowBroughtForward = nil;
        BOOL process = FALSE;

        if ([window isKindOfClass:[WineWindow class]] &&
            type == NSEventTypeLeftMouseDown &&
            ![theEvent wine_commandKeyDown])
        {
            NSWindowButton windowButton;

            windowBroughtForward = window;

            /* Any left-click on our window anyplace other than the close or
               minimize buttons will bring it forward. */
            for (windowButton = NSWindowCloseButton;
                 windowButton <= NSWindowMiniaturizeButton;
                 windowButton++)
            {
                NSButton* button = [window standardWindowButton:windowButton];
                if (button)
                {
                    NSPoint point = [button convertPoint:[theEvent locationInWindow] fromView:nil];
                    if ([button mouse:point inRect:[button bounds]])
                    {
                        windowBroughtForward = nil;
                        break;
                    }
                }
            }
        }

        if ([windowsBeingDragged count])
            window = nil;
        else if (mouseCaptureWindow)
            window = mouseCaptureWindow;

        if ([window isKindOfClass:[WineWindow class]])
        {
            BOOL pressed = (type == NSEventTypeLeftMouseDown ||
                            type == NSEventTypeRightMouseDown ||
                            type == NSEventTypeOtherMouseDown);
            CGPoint pt = CGEventGetLocation([theEvent CGEvent]);

            if (self.clippingCursor)
                [clipCursorHandler clipCursorLocation:&pt];

            if (pressed)
            {
                if (mouseCaptureWindow)
                    process = TRUE;
                else
                {
                    // Test if the click was in the window's content area.
                    NSPoint nspoint = [self flippedMouseLocation:NSPointFromCGPoint(pt)];
                    NSRect contentRect = [window contentRectForFrameRect:[window frame]];
                    process = NSMouseInRect(nspoint, contentRect, NO);
                    if (process && [window styleMask] & NSWindowStyleMaskResizable)
                    {
                        // Ignore clicks in the grow box (resize widget).
                        HIPoint origin = { 0, 0 };
                        HIThemeGrowBoxDrawInfo info = { 0 };
                        HIRect bounds;
                        OSStatus status;

                        info.kind = kHIThemeGrowBoxKindNormal;
                        info.direction = kThemeGrowRight | kThemeGrowDown;
                        if ([window styleMask] & NSWindowStyleMaskUtilityWindow)
                            info.size = kHIThemeGrowBoxSizeSmall;
                        else
                            info.size = kHIThemeGrowBoxSizeNormal;

                        status = HIThemeGetGrowBoxBounds(&origin, &info, &bounds);
                        if (status == noErr)
                        {
                            NSRect growBox = NSMakeRect(NSMaxX(contentRect) - bounds.size.width,
                                                        NSMinY(contentRect),
                                                        bounds.size.width,
                                                        bounds.size.height);
                            process = !NSMouseInRect(nspoint, growBox, NO);
                        }
                    }
                }
                if (process)
                    unmatchedMouseDowns |= NSEventMaskFromType(type);
            }
            else
            {
                NSEventType downType = type - 1;
                NSUInteger downMask = NSEventMaskFromType(downType);
                process = (unmatchedMouseDowns & downMask) != 0;
                unmatchedMouseDowns &= ~downMask;
            }

            if (process)
            {
                macdrv_event* event;

                pt = cgpoint_win_from_mac(pt);

                event = macdrv_create_event(MOUSE_BUTTON, window);
                event->mouse_button.button = [theEvent buttonNumber];
                event->mouse_button.pressed = pressed;
                event->mouse_button.x = floor(pt.x);
                event->mouse_button.y = floor(pt.y);
                event->mouse_button.time_ms = [self ticksForEventTime:[theEvent timestamp]];

                [window.queue postEvent:event];

                macdrv_release_event(event);
            }
        }

        if (windowBroughtForward)
        {
            WineWindow* ancestor = [windowBroughtForward ancestorWineWindow];
            NSInteger ancestorNumber = [ancestor windowNumber];
            NSInteger ancestorLevel = [ancestor level];

            for (NSNumber* windowNumberObject in [NSWindow windowNumbersWithOptions:0])
            {
                NSInteger windowNumber = [windowNumberObject integerValue];
                if (windowNumber == ancestorNumber)
                    break;
                WineWindow* otherWindow = (WineWindow*)[NSApp windowWithWindowNumber:windowNumber];
                if ([otherWindow isKindOfClass:[WineWindow class]] && [otherWindow screen] &&
                    [otherWindow level] <= ancestorLevel && otherWindow == [otherWindow ancestorWineWindow])
                {
                    [ancestor postBroughtForwardEvent];
                    break;
                }
            }
            if (!process && ![windowBroughtForward isKeyWindow] && !windowBroughtForward.disabled && !windowBroughtForward.noForeground)
                [self windowGotFocus:windowBroughtForward];
        }

        // Since mouse button events deliver absolute cursor position, the
        // accumulating delta from move events is invalidated.  Make sure
        // next mouse move event starts over from an absolute baseline.
        // Also, it's at least possible that the title bar widgets (e.g. close
        // button, etc.) could enter an internal event loop on a mouse down that
        // wouldn't exit until a mouse up.  In that case, we'd miss any mouse
        // dragged events and, after that, any notion of the cursor position
        // computed from accumulating deltas would be wrong.
        forceNextMouseMoveAbsolute = TRUE;
    }

    - (void) handleScrollWheel:(NSEvent*)theEvent
    {
        WineWindow* window;

        if (mouseCaptureWindow)
            window = mouseCaptureWindow;
        else
            window = (WineWindow*)[theEvent window];

        if ([window isKindOfClass:[WineWindow class]])
        {
            CGEventRef cgevent = [theEvent CGEvent];
            CGPoint pt = CGEventGetLocation(cgevent);
            BOOL process;

            if (self.clippingCursor)
                [clipCursorHandler clipCursorLocation:&pt];

            if (mouseCaptureWindow)
                process = TRUE;
            else
            {
                // Only process the event if it was in the window's content area.
                NSPoint nspoint = [self flippedMouseLocation:NSPointFromCGPoint(pt)];
                NSRect contentRect = [window contentRectForFrameRect:[window frame]];
                process = NSMouseInRect(nspoint, contentRect, NO);
            }

            if (process)
            {
                macdrv_event* event;
                double x, y;
                BOOL continuous = FALSE;

                pt = cgpoint_win_from_mac(pt);

                event = macdrv_create_event(MOUSE_SCROLL, window);
                event->mouse_scroll.x = floor(pt.x);
                event->mouse_scroll.y = floor(pt.y);
                event->mouse_scroll.time_ms = [self ticksForEventTime:[theEvent timestamp]];

                if (CGEventGetIntegerValueField(cgevent, kCGScrollWheelEventIsContinuous))
                {
                    continuous = TRUE;

                    /* Continuous scroll wheel events come from high-precision scrolling
                       hardware like Apple's Magic Mouse, Mighty Mouse, and trackpads.
                       For these, we can get more precise data from the CGEvent API. */
                    /* Axis 1 is vertical, axis 2 is horizontal. */
                    x = CGEventGetDoubleValueField(cgevent, kCGScrollWheelEventPointDeltaAxis2);
                    y = CGEventGetDoubleValueField(cgevent, kCGScrollWheelEventPointDeltaAxis1);
                }
                else
                {
                    double pixelsPerLine = 10;
                    CGEventSourceRef source;

                    /* The non-continuous values are in units of "lines", not pixels. */
                    if ((source = CGEventCreateSourceFromEvent(cgevent)))
                    {
                        pixelsPerLine = CGEventSourceGetPixelsPerLine(source);
                        CFRelease(source);
                    }

                    x = pixelsPerLine * [theEvent deltaX];
                    y = pixelsPerLine * [theEvent deltaY];
                }

                /* Mac: negative is right or down, positive is left or up.
                   Win32: negative is left or down, positive is right or up.
                   So, negate the X scroll value to translate. */
                x = -x;

                /* The x,y values so far are in pixels.  Win32 expects to receive some
                   fraction of WHEEL_DELTA == 120.  By my estimation, that's roughly
                   6 times the pixel value. */
                x *= 6;
                y *= 6;

                if (use_precise_scrolling)
                {
                    event->mouse_scroll.x_scroll = x;
                    event->mouse_scroll.y_scroll = y;

                    if (!continuous)
                    {
                        /* For non-continuous "clicky" wheels, if there was any motion, make
                           sure there was at least WHEEL_DELTA motion.  This is so, at slow
                           speeds where the system's acceleration curve is actually reducing the
                           scroll distance, the user is sure to get some action out of each click.
                           For example, this is important for rotating though weapons in a
                           first-person shooter. */
                        if (0 < event->mouse_scroll.x_scroll && event->mouse_scroll.x_scroll < 120)
                            event->mouse_scroll.x_scroll = 120;
                        else if (-120 < event->mouse_scroll.x_scroll && event->mouse_scroll.x_scroll < 0)
                            event->mouse_scroll.x_scroll = -120;

                        if (0 < event->mouse_scroll.y_scroll && event->mouse_scroll.y_scroll < 120)
                            event->mouse_scroll.y_scroll = 120;
                        else if (-120 < event->mouse_scroll.y_scroll && event->mouse_scroll.y_scroll < 0)
                            event->mouse_scroll.y_scroll = -120;
                    }
                }
                else
                {
                    /* If it's been a while since the last scroll event or if the scrolling has
                       reversed direction, reset the accumulated scroll value. */
                    if ([theEvent timestamp] - lastScrollTime > 1)
                        accumScrollX = accumScrollY = 0;
                    else
                    {
                        /* The accumulated scroll value is in the opposite direction/sign of the last
                           scroll.  That's because it's the "debt" resulting from over-scrolling in
                           that direction.  We accumulate by adding in the scroll amount and then, if
                           it has the same sign as the scroll value, we subtract any whole or partial
                           WHEEL_DELTAs, leaving it 0 or the opposite sign.  So, the user switched
                           scroll direction if the accumulated debt and the new scroll value have the
                           same sign. */
                        if ((accumScrollX < 0 && x < 0) || (accumScrollX > 0 && x > 0))
                            accumScrollX = 0;
                        if ((accumScrollY < 0 && y < 0) || (accumScrollY > 0 && y > 0))
                            accumScrollY = 0;
                    }
                    lastScrollTime = [theEvent timestamp];

                    accumScrollX += x;
                    accumScrollY += y;

                    if (accumScrollX > 0 && x > 0)
                        event->mouse_scroll.x_scroll = 120 * ceil(accumScrollX / 120);
                    if (accumScrollX < 0 && x < 0)
                        event->mouse_scroll.x_scroll = 120 * -ceil(-accumScrollX / 120);
                    if (accumScrollY > 0 && y > 0)
                        event->mouse_scroll.y_scroll = 120 * ceil(accumScrollY / 120);
                    if (accumScrollY < 0 && y < 0)
                        event->mouse_scroll.y_scroll = 120 * -ceil(-accumScrollY / 120);

                    accumScrollX -= event->mouse_scroll.x_scroll;
                    accumScrollY -= event->mouse_scroll.y_scroll;
                }

                if (event->mouse_scroll.x_scroll || event->mouse_scroll.y_scroll)
                    [window.queue postEvent:event];

                macdrv_release_event(event);

                // Since scroll wheel events deliver absolute cursor position, the
                // accumulating delta from move events is invalidated.  Make sure next
                // mouse move event starts over from an absolute baseline.
                forceNextMouseMoveAbsolute = TRUE;
            }
        }
    }

    // Returns TRUE if the event was handled and caller should do nothing more
    // with it.  Returns FALSE if the caller should process it as normal and
    // then call -didSendEvent:.
    - (BOOL) handleEvent:(NSEvent*)anEvent
    {
        BOOL ret = FALSE;
        NSEventType type = [anEvent type];

        if (type == NSEventTypeFlagsChanged)
            self.lastFlagsChanged = anEvent;
        else if (type == NSEventTypeMouseMoved || type == NSEventTypeLeftMouseDragged ||
                 type == NSEventTypeRightMouseDragged || type == NSEventTypeOtherMouseDragged)
        {
            [self handleMouseMove:anEvent];
            ret = mouseCaptureWindow && ![windowsBeingDragged count];
        }
        else if (type == NSEventTypeLeftMouseDown || type == NSEventTypeLeftMouseUp ||
                 type == NSEventTypeRightMouseDown || type == NSEventTypeRightMouseUp ||
                 type == NSEventTypeOtherMouseDown || type == NSEventTypeOtherMouseUp)
        {
            [self handleMouseButton:anEvent];
            ret = mouseCaptureWindow && ![windowsBeingDragged count];
        }
        else if (type == NSEventTypeScrollWheel)
        {
            [self handleScrollWheel:anEvent];
            ret = mouseCaptureWindow != nil;
        }
        else if (type == NSEventTypeKeyDown)
        {
            // -[NSApplication sendEvent:] seems to consume presses of the Help
            // key (Insert key on PC keyboards), so we have to bypass it and
            // send the event directly to the window.
            if (anEvent.keyCode == kVK_Help)
            {
                [anEvent.window sendEvent:anEvent];
                ret = TRUE;
            }
        }
        else if (type == NSEventTypeKeyUp)
        {
            uint16_t keyCode = [anEvent keyCode];
            if ([self isKeyPressed:keyCode])
            {
                WineWindow* window = (WineWindow*)[anEvent window];
                [self noteKey:keyCode pressed:FALSE];
                if ([window isKindOfClass:[WineWindow class]])
                    [window postKeyEvent:anEvent];
            }
        }

        return ret;
    }

    - (void) didSendEvent:(NSEvent*)anEvent
    {
        NSEventType type = [anEvent type];

        if (type == NSEventTypeKeyDown && ![anEvent isARepeat] && [anEvent keyCode] == kVK_Tab)
        {
            NSUInteger modifiers = [anEvent modifierFlags];
            if ((modifiers & NSEventModifierFlagCommand) &&
                !(modifiers & (NSEventModifierFlagControl | NSEventModifierFlagOption)))
            {
                // Command-Tab and Command-Shift-Tab would normally be intercepted
                // by the system to switch applications.  If we're seeing it, it's
                // presumably because we've captured the displays, preventing
                // normal application switching.  Do it manually.
                [self handleCommandTab];
            }
        }
    }

    - (void) setupObservations
    {
        NSNotificationCenter* nc = [NSNotificationCenter defaultCenter];
        NSNotificationCenter* wsnc = [[NSWorkspace sharedWorkspace] notificationCenter];
        NSDistributedNotificationCenter* dnc = [NSDistributedNotificationCenter defaultCenter];

        [nc addObserverForName:NSWindowDidBecomeKeyNotification
                        object:nil
                         queue:nil
                    usingBlock:^(NSNotification *note){
            NSWindow* window = [note object];
            [keyWindows removeObjectIdenticalTo:window];
            [keyWindows insertObject:window atIndex:0];
        }];

        [nc addObserverForName:NSWindowWillCloseNotification
                        object:nil
                         queue:[NSOperationQueue mainQueue]
                    usingBlock:^(NSNotification *note){
            /* Always defensively re-couple the mouse when ANY window closes -
             * if the game decoupled it for FPS mode, our shutdown path stops
             * receiving mouseMoved events so the explicit revert in mouseMoved
             * never fires. Without this, _ReleaseMetalView's OnMainThread
             * dispatch_sync hangs because Cocoa's run loop becomes unresponsive
             * with the mouse in disassociated state. */
            macdrv_restore_mouse_association();

            NSWindow* window = [note object];
            if ([window isKindOfClass:[WineWindow class]] && [(WineWindow*)window isFakingClose])
                return;
            [keyWindows removeObjectIdenticalTo:window];
            if (window == lastTargetWindow)
                lastTargetWindow = nil;
            if (window == self.mouseCaptureWindow)
            {
                self.mouseCaptureWindow = nil;
                self.mouseCaptureIsMoveSize = NO;
            }
            if ([window isKindOfClass:[WineWindow class]] && [(WineWindow*)window isFullscreen])
            {
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0), dispatch_get_main_queue(), ^{
                    [self updateFullscreenWindows];
                });
            }
            [windowsBeingDragged removeObject:window];
        }];

        [nc addObserverForName:NSWindowWillStartDraggingNotification
                        object:nil
                         queue:[NSOperationQueue mainQueue]
                    usingBlock:^(NSNotification *note){
            NSWindow* window = [note object];
            if ([window isKindOfClass:[WineWindow class]])
                [self handleWindowDrag:(WineWindow *)window begin:YES];
        }];

        [nc addObserverForName:NSWindowDidEndDraggingNotification
                        object:nil
                         queue:[NSOperationQueue mainQueue]
                    usingBlock:^(NSNotification *note){
            NSWindow* window = [note object];
            if ([window isKindOfClass:[WineWindow class]])
                [self handleWindowDrag:(WineWindow *)window begin:NO];
        }];

        [nc addObserver:self
               selector:@selector(keyboardSelectionDidChange)
                   name:NSTextInputContextKeyboardSelectionDidChangeNotification
                 object:nil];

        /* The above notification isn't sent unless the NSTextInputContext
           class has initialized itself.  Poke it. */
        [NSTextInputContext self];

        [wsnc addObserver:self
                 selector:@selector(activeSpaceDidChange)
                     name:NSWorkspaceActiveSpaceDidChangeNotification
                   object:nil];

        [nc addObserver:self
               selector:@selector(releaseMouseCapture)
                   name:NSMenuDidBeginTrackingNotification
                 object:nil];

        [dnc        addObserver:self
                       selector:@selector(releaseMouseCapture)
                           name:@"com.apple.HIToolbox.beginMenuTrackingNotification"
                         object:nil
             suspensionBehavior:NSNotificationSuspensionBehaviorDrop];

        [dnc addObserver:self
                selector:@selector(enabledKeyboardInputSourcesChanged)
                    name:(NSString*)kTISNotifyEnabledKeyboardInputSourcesChanged
                  object:nil];

        /* Strategy E.1: cross-process CAMetalLayer hosting. DXMT in process A
         * creates a CAMetalLayer + CAContext, broadcasts (hwnd, contextId, pid)
         * via NSDistributedNotification. Each Wine process listens; the one
         * owning the HWND inserts CALayerHost(contextId:) into its
         * WineContentView's layer tree, causing WindowServer to composite
         * process A's drawables INTO process B's NSWindow. */
        /* Strategy E.1 observer can be disabled at runtime via the
         * PROTON_DISABLE_E1 env var. Modern Steam (steam.exe + steamwebhelper)
         * crashes early in CEF init when E.1 is enabled - likely a
         * winemac.drv regression vs upstream/CrossOver Wine. Setting
         * PROTON_DISABLE_E1=1 makes winemac.drv behave like upstream
         * (no cross-process layer-host notifications), at the cost of
         * losing E.1's DX12-cross-process layer hosting for game prefixes
         * that depend on it (Elden Ring, Witcher 3 DX12 path). Game
         * prefixes leave PROTON_DISABLE_E1 unset; only the Steam-in-bottle
         * launch turns it on. */
        /* Bug (Proton macOS) 2026-04-29: scope PROTON_DISABLE_E1 to the
         * processes that actually need it. CreateProcess inheritance
         * propagates Steam's env to every game it launches, breaking DXMT
         * (Hades's DXMTRemoteLayerHostRequest gets no host) for games
         * launched via `steam.exe -applaunch`. Honor PROTON_DISABLE_E1
         * only for steam.exe / steamwebhelper.exe / cef.win64
         * subprocesses; ignore it for everything else. */
        BOOL disable_e1 = NO;
        /* PROTON_DISABLE_E1_ALL: process-agnostic kill switch. The per-process
         * arg-suffix detection below is unreliable for Steam's CEF subprocesses
         * (steamwebhelper child processes) - their NSProcessInfo arguments do not
         * carry the .exe path in a matching form, so they ignore PROTON_DISABLE_E1,
         * keep the E.1 layer-host observer, and attach an opaque overlay over the
         * CEF software UI -> black window. In Steam-in-bottle (login-UI) mode there
         * are no games, so disabling E.1 in EVERY process is correct. */
        if (getenv("PROTON_DISABLE_E1_ALL"))
        {
            disable_e1 = YES;
        }
        else if (getenv("PROTON_DISABLE_E1"))
        {
            NSArray *argv = [[NSProcessInfo processInfo] arguments];
            for (NSString *arg in argv)
            {
                NSString *lower = [arg lowercaseString];
                if ([lower hasSuffix:@"\\steam.exe"] ||
                    [lower hasSuffix:@"/steam.exe"] ||
                    [lower hasSuffix:@"\\steamwebhelper.exe"] ||
                    [lower hasSuffix:@"/steamwebhelper.exe"] ||
                    [lower hasSuffix:@"\\gldriverquery.exe"] ||
                    [lower hasSuffix:@"/gldriverquery.exe"] ||
                    [lower hasSuffix:@"\\gldriverquery64.exe"] ||
                    [lower hasSuffix:@"/gldriverquery64.exe"])
                {
                    disable_e1 = YES;
                    break;
                }
            }
            if (!disable_e1)
                fprintf(stderr, "winemac:E.1 - pid=%d ignoring PROTON_DISABLE_E1 (process is not steam-related)\n",
                        getpid());
        }
        if (!disable_e1)
        {
            [dnc addObserver:self
                    selector:@selector(handleDXMTRemoteLayerHostRequest:)
                        name:@"DXMTRemoteLayerHostRequest"
                      object:nil
          suspensionBehavior:NSNotificationSuspensionBehaviorDeliverImmediately];
            fprintf(stderr, "winemac:E.1 - pid=%d registered observer for DXMTRemoteLayerHostRequest\n", getpid());
        }
        else
        {
            fprintf(stderr, "winemac:E.1 - pid=%d skipped observer (PROTON_DISABLE_E1=1)\n", getpid());
        }

        if ([NSApplication instancesRespondToSelector:@selector(yieldActivationToApplication:)])
        {
            /* App activation cooperation, starting in macOS 14 Sonoma. */
            [dnc addObserver:self
                    selector:@selector(otherWineAppWillActivate:)
                        name:WineAppWillActivateNotification
                      object:nil
          suspensionBehavior:NSNotificationSuspensionBehaviorDeliverImmediately];
        }
    }

    /* Strategy E.1 handler - see setupObservations for design notes. */
    - (void) handleDXMTRemoteLayerHostRequest:(NSNotification *)note
    {
        extern void *macdrv_resolve_hwnd_for_hosting(void *hwnd, void **out_hwnd, int *out_is_window);

        NSDictionary *info = [note userInfo];
        void *hwnd = (void *)(uintptr_t)[(NSNumber *)info[@"hwnd"] unsignedLongLongValue];
        uint32_t contextId = [(NSNumber *)info[@"contextId"] unsignedIntValue];
        int senderPid = [(NSNumber *)info[@"pid"] intValue];

        fprintf(stderr, "winemac:E.1 - pid=%d received DXMTRemoteLayerHostRequest hwnd=%p ctxId=%u senderPid=%d\n",
                getpid(), hwnd, contextId, senderPid);
        (void)senderPid; /* same-process is fine: game and DXMT live together */

        /* Queued 0052 [E1-DIAG]: discriminate failure-mode (A) "broadcast not received". */
        if (proton_e1_diag_enabled()) {
            fprintf(stderr, "winemac:[E1-DIAG] receive pid=%d hwnd=%p ctxId=%u senderPid=%d sameProc=%d\n",
                    getpid(), hwnd, contextId, senderPid, (int)(senderPid == getpid()));
            fflush(stderr);
        }

        void *outHwnd = NULL;
        int isWindow = 0;
        void *target = macdrv_resolve_hwnd_for_hosting(hwnd, &outHwnd, &isWindow);
        fprintf(stderr, "winemac:E.1 - pid=%d resolver returned hwnd=%p target=%p isWindow=%d\n",
                getpid(), outHwnd, target, isWindow);
        /* Queued 0052 [E1-DIAG]: discriminate failure-mode (B) "owner also empty win_data". */
        if (proton_e1_diag_enabled()) {
            fprintf(stderr, "winemac:[E1-DIAG] resolve pid=%d target=%p outHwnd=%p isWindow=%d\n",
                    getpid(), target, outHwnd, isWindow);
            fflush(stderr);
        }
        if (!target) {
            if (proton_e1_diag_enabled()) {
                fprintf(stderr, "winemac:[E1-DIAG] receiveAbort reason=noTarget pid=%d hwnd=%p\n",
                        getpid(), hwnd);
                fflush(stderr);
            }
            return;
        }

        BOOL sameProcess = (senderPid == getpid());
        uintptr_t layerPtrVal = [(NSNumber *)info[@"layerPtr"] unsignedLongLongValue];

        dispatch_async(dispatch_get_main_queue(), ^{
            NSView *view;
            if (isWindow) {
                NSWindow *win = (__bridge NSWindow *)target;
                view = [win contentView];
                fprintf(stderr, "winemac:E.1 - using NSWindow=%p contentView=%p\n", (void *)win, (void *)view);
            } else {
                view = (__bridge NSView *)target;
            }
            if (!view) {
                fprintf(stderr, "winemac:E.1 - no view available\n");
                if (proton_e1_diag_enabled()) {
                    fprintf(stderr, "winemac:[E1-DIAG] receiveAbort reason=noView pid=%d hwnd=%p\n",
                            getpid(), hwnd);
                    fflush(stderr);
                }
                return;
            }
            [view setWantsLayer:YES];
            CALayer *parentLayer = [view layer];
            if (!parentLayer) {
                fprintf(stderr, "winemac:E.1 - view=%p has no layer (after wantsLayer)\n", (void *)view);
                if (proton_e1_diag_enabled()) {
                    fprintf(stderr, "winemac:[E1-DIAG] receiveAbort reason=noParentLayer pid=%d hwnd=%p view=%p\n",
                            getpid(), hwnd, (void *)view);
                    fflush(stderr);
                }
                return;
            }

            /* Strategy E.1 software-window guard (Proton macOS 2026-06-20):
             * Steam's CEF UI is SOFTWARE-rendered. Its GPU subprocess still
             * creates a Vulkan surface (then crashes + software-falls-back),
             * which broadcasts DXMTRemoteLayerHostRequest. If we attach the
             * opaque black CAMetalLayer/CALayerHost overlay (zPosition 1000)
             * onto that window's contentView, it occludes the software CEF
             * bitmap that lands in the same view's layer.contents -> black.
             *
             * DECLINE attaching when the target is a WineContentView with a
             * live colorImage (a software paint target). Real Vulkan game
             * windows (DOOM, Hades) never set colorImage, so they are
             * unaffected and still get their overlay.
             *
             * RACE: the broadcast can arrive BEFORE software fallback sets
             * colorImage, and broadcasts RETRY repeatedly. So on a (re)broadcast
             * where colorImage has since become non-nil, also REMOVE any overlay
             * we already attached, then return - the overlay goes away as soon
             * as the window has software content, and stays gone. */
            if ([view isKindOfClass:[WineContentView class]] &&
                [(WineContentView *)view hasLiveColorImage]) {
                NSArray *existing = [parentLayer.sublayers copy];
                int removed = 0;
                for (CALayer *sib in existing) {
                    if ([sib isKindOfClass:NSClassFromString(@"CAMetalLayer")] ||
                        [sib isKindOfClass:NSClassFromString(@"CALayerHost")]) {
                        [sib removeFromSuperlayer];
                        removed++;
                    }
                }
                fprintf(stderr, "winemac:E.1 - declining overlay (target has live software surface) view=%p removedExisting=%d\n",
                        (void *)view, removed);
                return;
            }

            /* Queued 0052 [E1-DIAG]: discriminate failure-mode (C) "view hidden / unparented / 0x0 frame". */
            if (proton_e1_diag_enabled()) {
                NSRect winFrame = view.window ? [view.window frame] : NSZeroRect;
                fprintf(stderr,
                        "winemac:[E1-DIAG] view pid=%d view=%p layer=%p viewHidden=%d windowVisible=%d windowKey=%d viewSuperview=%p windowFrame=%gx%g\n",
                        getpid(), (void *)view, (void *)parentLayer,
                        (int)[view isHidden], (int)[view.window isVisible], (int)[view.window isKeyWindow],
                        (void *)[view superview], winFrame.size.width, winFrame.size.height);
                fflush(stderr);
            }

            CALayer *child = nil;
            if (sameProcess && layerPtrVal) {
                /* Same process: attach the CAMetalLayer directly. CALayerHost
                 * is only for cross-process hosting - using it in-process leaves
                 * the layer empty. */
                child = (__bridge CALayer *)(void *)layerPtrVal;
                fprintf(stderr,
                        "winemac:E.1 - same-process direct CAMetalLayer attach: layer=%p (current superlayer=%p, parent=%p, parent has %lu sublayers)\n",
                        (void *)child, (void *)child.superlayer, (void *)parentLayer,
                        (unsigned long)parentLayer.sublayers.count);
            } else {
                Class hostCls = NSClassFromString(@"CALayerHost");
                if (!hostCls) {
                    fprintf(stderr, "winemac:E.1 - CALayerHost class unavailable\n");
                    return;
                }
                child = [[hostCls alloc] init];
                [child setValue:@(contextId) forKey:@"contextId"];
                fprintf(stderr, "winemac:E.1 - cross-process CALayerHost(ctx=%u)\n", contextId);
            }
            /* Bug (Proton macOS) 2026-04-29: parentLayer.bounds is often
             * 0×0 at attach time because the view's backing layer hasn't
             * been laid out yet (NSView's `bounds` is set by the window
             * resize machinery before the layer's `bounds` is updated).
             * Use the view's bounds instead - they're populated by the
             * time we get here (window opened → contentView resized →
             * E.1 broadcast fires → we attach). Without this, MoltenVK
             * renders 1512×982 swapchain images into a CAMetalLayer with
             * frame=0×0, the layer occupies zero visible area on the
             * parent view, and the user sees the parent NSWindow's
             * white background instead of the rendered content. */
            CGRect attachFrame = parentLayer.bounds;
            if (attachFrame.size.width < 1 || attachFrame.size.height < 1)
            {
                NSRect viewBounds = view.bounds;
                attachFrame = NSRectToCGRect(viewBounds);
                fprintf(stderr, "winemac:E.1 - parentLayer.bounds was %gx%g, falling back to view.bounds=%gx%g\n",
                        parentLayer.bounds.size.width, parentLayer.bounds.size.height,
                        attachFrame.size.width, attachFrame.size.height);
            }
            /* Bug (Proton macOS) 2026-04-30: after Cmd-Tab away/back from a
             * fullscreen Vulkan game (DOOM), Cocoa's fullscreen-exit/re-enter
             * transition leaves view.bounds AND parentLayer.bounds both at
             * 0×0 mid-transition. We end up attaching CAMetalLayers sized 0×0
             * to a window that returns to fullscreen seconds later - the
             * layers never resize, the user sees a white window. Fall back to
             * the window's frame size, then to the screen size, so the
             * autoresizingMask has something non-zero to scale from. */
            if (attachFrame.size.width < 1 || attachFrame.size.height < 1)
            {
                CGSize fallback = CGSizeZero;
                if (view.window) {
                    NSRect winFrame = [view.window frame];
                    fallback = winFrame.size;
                }
                if (fallback.width < 1 || fallback.height < 1) {
                    NSScreen *screen = view.window.screen ?: [NSScreen mainScreen];
                    if (screen) fallback = screen.frame.size;
                }
                if (fallback.width >= 1 && fallback.height >= 1) {
                    attachFrame = (CGRect){{0, 0}, fallback};
                    fprintf(stderr, "winemac:E.1 - view.bounds also 0x0, using window/screen fallback %gx%g\n",
                            fallback.width, fallback.height);
                }
            }
            /* Bug (Proton macOS) 2026-05-05: wrap all layer property mutations
             * in a CATransaction with implicit actions disabled. Setting
             * .frame / .contentsScale / .autoresizingMask on an already-
             * attached CALayer would otherwise fire CA's default 0.25s
             * implicit animation (kCAOnOrderInAnimation et al). Each E.1
             * broadcast re-sets these properties, so without this the user
             * sees a flicker every time DXMT/winevulkan re-broadcasts
             * (which happens repeatedly during normal rendering as well as
             * on focus / resize events). Cmd-Tab "fixes" the flicker
             * because windowDidBecomeKey forces a synchronous layout that
             * skips past the in-flight animation. */
            [CATransaction begin];
            [CATransaction setDisableActions:YES];

            child.frame = attachFrame;
            child.contentsScale = parentLayer.contentsScale ?: 1.0;
            child.zPosition = 1000.0; /* Force on top of any sibling layers */
            /* Auto-resize with parent (window resize / fullscreen toggle) and
             * stretch contents to fill - avoids gaps on right/bottom when the
             * drawable's logical size is smaller than the contentView's
             * point-bounds (typical at fullscreen on Retina). */
            child.autoresizingMask = kCALayerWidthSizable | kCALayerHeightSizable;
            child.contentsGravity = kCAGravityResize;

            /* Remove any prior CALayerHost / CAMetalLayer we already attached
             * for this view (from earlier broadcast retries). */
            NSArray *existing = [parentLayer.sublayers copy];
            for (CALayer *sib in existing) {
                if ([sib isKindOfClass:NSClassFromString(@"CAMetalLayer")] ||
                    [sib isKindOfClass:NSClassFromString(@"CALayerHost")]) {
                    if (sib != child) [sib removeFromSuperlayer];
                }
            }
            if (child.superlayer != parentLayer) [parentLayer addSublayer:child];

            [CATransaction commit];

            /* Stamp this hwnd so the broadcaster's retry timer (running in
             * the same process for same-process attach, the common case)
             * stops re-broadcasting once we've successfully hosted the
             * layer. See comment in macdrv_broadcast_vulkan_layer_host_request
             * for why the retries cause flicker. */
            if (sameProcess) {
                if (!s_e1AttachedHwnds) s_e1AttachedHwnds = [[NSMutableSet alloc] init];
                [s_e1AttachedHwnds addObject:@((uintptr_t)hwnd)];
            }

            /* Bug (Proton macOS) 2026-04-30: macdrv_client_surface_present
             * hides the old client_view when it swaps in the surface's
             * cocoa_view - but on the first surface for a window the old
             * client_view IS the cocoa_window's contentView. Hiding that
             * makes the entire subtree (including our newly-attached
             * CAMetalLayer) invisible: the user sees the NSWindow's white
             * background. Force the view chain visible up to the window. */
            {
                NSView *vv = view;
                int unhid = 0;
                while (vv) {
                    if ([vv isHidden]) {
                        [vv setHidden:NO];
                        unhid++;
                    }
                    vv = [vv superview];
                }
                if (unhid)
                    fprintf(stderr, "winemac:E.1 - un-hid %d ancestor view(s) for view=%p\n",
                            unhid, (void *)view);
            }

            /* The retry-arm we tried earlier (re-broadcasting until
             * windowVisible=1) was wrong: each broadcast spawns a new
             * CAMetalLayer-CAContext instance, leaving 8 dead surfaces queued
             * by retry exhaustion time. The screen-size fallback above
             * provides a non-zero attach frame even mid-transition; the
             * autoresizingMask handles the resize when the window settles. */

            fprintf(stderr, "winemac:E.1 - hosted child=%p onto view=%p layer=%p (frame=%gx%g, scale=%g, %lu sublayers) sameProc=%d viewHidden=%d windowVisible=%d\n",
                    (void *)child, (void *)view, (void *)parentLayer,
                    parentLayer.bounds.size.width, parentLayer.bounds.size.height,
                    parentLayer.contentsScale, (unsigned long)parentLayer.sublayers.count, sameProcess,
                    [view isHidden], [view.window isVisible]);

            /* Queued 0052 [E1-DIAG]: confirm attach committed; correlates with publish on senderPid. */
            if (proton_e1_diag_enabled()) {
                fprintf(stderr,
                        "winemac:[E1-DIAG] attach ok pid=%d child=%p childFrame=%gx%g childContents=%p parentSublayers=%lu sameProc=%d\n",
                        getpid(), (void *)child, child.frame.size.width, child.frame.size.height,
                        (void *)child.contents, (unsigned long)parentLayer.sublayers.count, (int)sameProcess);
                fflush(stderr);
            }
        });
    }

    - (void) otherWineAppWillActivate:(NSNotification *)note
    {
        NSProcessInfo *ourProcess;
        pid_t otherPID;
        NSString *ourConfigDir, *otherConfigDir, *ourPrefix, *otherPrefix;
        NSRunningApplication *otherApp;

        /* No point in yielding if we're not the foreground app. */
        if (![NSApp isActive]) return;

        /* Ignore requests from ourself, dead processes, and other prefixes. */
        ourProcess = [NSProcessInfo processInfo];
        otherPID = [note.userInfo[WineActivatingAppPIDKey] integerValue];
        if (otherPID == ourProcess.processIdentifier) return;

        otherApp = [NSRunningApplication runningApplicationWithProcessIdentifier:otherPID];
        if (!otherApp) return;

        ourConfigDir = ourProcess.environment[@"WINECONFIGDIR"];
        otherConfigDir = note.userInfo[WineActivatingAppConfigDirKey];
        if (ourConfigDir.length && otherConfigDir.length &&
            ![ourConfigDir isEqualToString:otherConfigDir])
        {
            return;
        }

        ourPrefix = ourProcess.environment[@"WINEPREFIX"];
        otherPrefix = note.userInfo[WineActivatingAppPrefixKey];
        if (ourPrefix.length && otherPrefix.length &&
            ![ourPrefix isEqualToString:otherPrefix])
        {
            return;
        }

        /* There's a race condition here. The requesting app sends out
           WineAppWillActivateNotification and then activates itself, but since
           distributed notifications are asynchronous, we may not have yielded
           in time. So we call activateFromApplication: on the other app here,
           which will work around that race if it happened. If we didn't hit the
           race, the activateFromApplication: call will be a no-op. */

        /* We only add this observer if NSApplication responds to the yield
           methods, so they're safe to call without checking here. */
        [NSApp yieldActivationToApplication:otherApp];
        [otherApp activateFromApplication:[NSRunningApplication currentApplication]
                                  options:0];
    }

    - (void) tryToActivateIgnoringOtherApps:(BOOL)ignore
    {
        NSProcessInfo *processInfo;
        NSString *configDir, *prefix;
        NSDictionary *userInfo;

        if ([NSApp isActive]) return;  /* Nothing to do. */

        if (!ignore ||
            ![NSApplication instancesRespondToSelector:@selector(yieldActivationToApplication:)])
        {
            /* Either we don't need to force activation, or the OS is old enough
               that this is our only option. */
            [NSApp activateIgnoringOtherApps:ignore];
            return;
        }

        /* Ask other Wine apps to yield activation to us. */
        processInfo = [NSProcessInfo processInfo];
        configDir = processInfo.environment[@"WINECONFIGDIR"];
        prefix = processInfo.environment[@"WINEPREFIX"];
        userInfo = @{
            WineActivatingAppPIDKey: @(processInfo.processIdentifier),
            WineActivatingAppPrefixKey: prefix ? prefix : @"",
            WineActivatingAppConfigDirKey: configDir ? configDir : @""
        };

        [[NSDistributedNotificationCenter defaultCenter]
            postNotificationName:WineAppWillActivateNotification
                          object:nil
                        userInfo:userInfo
              deliverImmediately:YES];

        /* This is racy. See the note in otherWineAppWillActivate:. */
        [NSApp activate];
     }

    static BOOL InputSourceShouldBeIgnored(TISInputSourceRef inputSource)
    {
        /* Certain system utilities are technically input sources, but we
           shouldn't consider them as such for our purposes. */
        static CFStringRef ignoredIDs[] = {
            /* The "Emoji & Symbols" palette. */
            CFSTR("com.apple.CharacterPaletteIM"),
            /* The on-screen keyboard and accessibility panel. */
            CFSTR("com.apple.inputmethod.AssistiveControl"),
            /* The popup for accented characters when you hold down a key. */
            CFSTR("com.apple.PressAndHold"),
            /* Emoji list on MacBooks with the Touch Bar. */
            CFSTR("com.apple.inputmethod.EmojiFunctionRowItem"),
            /* Dictation. Ideally this would actually receive key events, since
               escape cancels it, but it remains a "selected" input source even
               when not active, so we need to ignore it to avoid incorrectly
               sending input to it. */
            CFSTR("com.apple.inputmethod.ironwood"),
        };

        CFStringRef sourceID = TISGetInputSourceProperty(inputSource, kTISPropertyInputSourceID);
        for (int i = 0; i < sizeof(ignoredIDs) / sizeof(CFStringRef); i++)
        {
            if (CFEqual(sourceID, ignoredIDs[i]))
                return YES;
        }

        return NO;
    }

    - (BOOL) inputSourceIsInputMethod
    {
        static dispatch_once_t onceToken;
        static CFDictionaryRef filterDict;
        CFArrayRef enabledSources;
        CFIndex i;
        BOOL ret = NO;

        /* There may be multiple active ("selected") input sources, but there is
           always exactly one selected keyboard input source. For instance,
           handwriting methods are active simultaneously with a keyboard source.
           As the name implies, TISCopyCurrentKeyboardInputSource only returns
           the keyboard source, so it's not sufficient for our needs. We use
           TISCreateInputSourceList instead to find all selected sources. */
        dispatch_once(&onceToken, ^{
            filterDict = CFDictionaryCreate(NULL, (const void **)&kTISPropertyInputSourceIsSelected, (const void **)&kCFBooleanTrue, 1,
                                            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

        });
        enabledSources = TISCreateInputSourceList(filterDict, false);
        for (i = 0; i < CFArrayGetCount(enabledSources); i++)
        {
            TISInputSourceRef source = (TISInputSourceRef)CFArrayGetValueAtIndex(enabledSources, i);
            CFStringRef type = TISGetInputSourceProperty(source, kTISPropertyInputSourceType);

            /* kTISTypeKeyboardLayout is for physical keyboards. Any type other
               than that is an IME. */
            if (!CFEqual(type, kTISTypeKeyboardLayout) && !InputSourceShouldBeIgnored(source))
            {
                ret = YES;
                break;
            }
        }

        CFRelease(enabledSources);
        return ret;
     }

    - (void) releaseMouseCapture
    {
        // This might be invoked on a background thread by the distributed
        // notification center.  Shunt it to the main thread.
        if (![NSThread isMainThread])
        {
            dispatch_async(dispatch_get_main_queue(), ^{ [self releaseMouseCapture]; });
            return;
        }

        if (mouseCaptureWindow)
        {
            macdrv_event* event;

            event = macdrv_create_event(RELEASE_CAPTURE, mouseCaptureWindow);
            [mouseCaptureWindow.queue postEvent:event];
            macdrv_release_event(event);
        }
    }

    - (void) unminimizeWindowIfNoneVisible
    {
        WineWindow *bestOption = nil;

        if ([self isAnyWineWindowVisible])
            return;

        for (WineWindow *window in [NSApp windows])
        {
            if (![window isKindOfClass:[WineWindow class]] || ![window isMiniaturized])
                continue;

            bestOption = window;

            /* Prefer any window that would actually show something. */
            if ([window presentsVisibleContent])
                break;
        }

        [bestOption deminiaturize:self];
    }

    - (void) setRetinaMode:(BOOL)mode
    {
        retina_on = mode;

        [clipCursorHandler setRetinaMode:mode];

        for (WineWindow* window in [NSApp windows])
        {
            if ([window isKindOfClass:[WineWindow class]])
                [window setRetinaMode:mode];
        }
    }


    /*
     * ---------- NSApplicationDelegate methods ----------
     */
    - (void)applicationDidBecomeActive:(NSNotification *)notification
    {
        NSNumber* displayID;
        NSDictionary* modesToRealize = [latentDisplayModes autorelease];

        latentDisplayModes = [[NSMutableDictionary alloc] init];
        for (displayID in modesToRealize)
        {
            CGDisplayModeRef mode = (CGDisplayModeRef)modesToRealize[displayID];
            [self setMode:mode forDisplay:[displayID unsignedIntValue]];
        }

        [self updateFullscreenWindows];
        [self adjustWindowLevels:YES];

        if (beenActive)
            [self unminimizeWindowIfNoneVisible];
        beenActive = TRUE;

        // If a Wine process terminates abruptly while it has the display captured
        // and switched to a different resolution, Mac OS X will uncapture the
        // displays and switch their resolutions back.  However, the other Wine
        // processes won't have their notion of the desktop rect changed back.
        // This can lead them to refuse to draw or acknowledge clicks in certain
        // portions of their windows.
        //
        // To solve this, we synthesize a displays-changed event whenever we're
        // activated.  This will provoke a re-synchronization of Wine's notion of
        // the desktop rect with the actual state.
        [self sendDisplaysChanged:TRUE];

        // The cursor probably moved while we were inactive.  Accumulated mouse
        // movement deltas are invalidated.  Make sure the next mouse move event
        // starts over from an absolute baseline.
        forceNextMouseMoveAbsolute = TRUE;
    }

    - (void)applicationDidChangeScreenParameters:(NSNotification *)notification
    {
        primaryScreenHeightValid = FALSE;
        [self sendDisplaysChanged:FALSE];
        [self adjustWindowLevels];

        // When the display configuration changes, the cursor position may jump.
        // Accumulated mouse movement deltas are invalidated.  Make sure the next
        // mouse move event starts over from an absolute baseline.
        forceNextMouseMoveAbsolute = TRUE;
    }

    - (void)applicationDidResignActive:(NSNotification *)notification
    {
        macdrv_event* event;
        WineEventQueue* queue;

        [self invalidateGotFocusEvents];

        event = macdrv_create_event(APP_DEACTIVATED, nil);

        [eventQueuesLock lock];
        for (queue in eventQueues)
            [queue postEvent:event];
        [eventQueuesLock unlock];

        macdrv_release_event(event);

        [self releaseMouseCapture];
        [self updateMenuBarHiding];
    }

    - (void) applicationDidUnhide:(NSNotification*)aNotification
    {
        [self adjustWindowLevels];
    }

    - (BOOL) applicationShouldHandleReopen:(NSApplication*)theApplication hasVisibleWindows:(BOOL)flag
    {
        // Note that "flag" is often wrong.  WineWindows are NSPanels and NSPanels
        // don't count as "visible windows" for this purpose.
        [self unminimizeWindowIfNoneVisible];
        return YES;
    }

    - (NSApplicationTerminateReply) applicationShouldTerminate:(NSApplication *)sender
    {
        NSApplicationTerminateReply ret = NSTerminateNow;
        NSAppleEventManager* m = [NSAppleEventManager sharedAppleEventManager];
        NSAppleEventDescriptor* desc = [m currentAppleEvent];
        int32_t quitReason = [[desc attributeDescriptorForKeyword:kAEQuitReason] int32Value];
        macdrv_event* event;
        WineEventQueue* queue;

        /* Defensive: in case FPS-mode disassociation is still active when
         * the user invokes Dock-Quit / Cmd-Q, re-couple the mouse + cursor
         * before we let Cocoa run its teardown. */
        macdrv_restore_mouse_association();

        event = macdrv_create_event(APP_QUIT_REQUESTED, nil);
        event->deliver = 1;
        switch (quitReason)
        {
            case kAELogOut:
            case kAEReallyLogOut:
                event->app_quit_requested.reason = QUIT_REASON_LOGOUT;
                break;
            case kAEShowRestartDialog:
                event->app_quit_requested.reason = QUIT_REASON_RESTART;
                break;
            case kAEShowShutdownDialog:
                event->app_quit_requested.reason = QUIT_REASON_SHUTDOWN;
                break;
            default:
                event->app_quit_requested.reason = QUIT_REASON_NONE;
                break;
        }

        [eventQueuesLock lock];

        if ([eventQueues count])
        {
            for (queue in eventQueues)
                [queue postEvent:event];
            ret = NSTerminateLater;
        }

        [eventQueuesLock unlock];

        macdrv_release_event(event);

        /* Bug (Proton macOS) 2026-04-29: macOS's Dock unresponsive-app
         * heuristic sends an unsolicited kAEQuitApplication when a
         * Wine bottle running a busy game momentarily stops draining
         * NSEvents. Returning NSTerminateLater puts the Cocoa main
         * thread in a nested `_shouldTerminate` event loop waiting
         * for `replyToApplicationShouldTerminate:` - but that reply
         * only fires after every Wine window pumps WM_QUERYENDSESSION.
         * If any window's owner thread is mid-stall (e.g. on
         * user_lock contention), the reply never comes and the Cocoa
         * main thread is permanently stuck - self-fueling because
         * the stuck main thread reinforces the Dock's unresponsive
         * verdict. See lldb bt at
         * docs/macos/experiments/sample-hades-lldb-bts-2026-04-29.txt.
         *
         * For the only AppleEvent quit reason that's truly load-
         * bearing (a logout / restart / shutdown - system is going
         * away) we still want to honor the request, so keep the
         * existing NSTerminateLater path. For QUIT_REASON_NONE
         * (typically Cmd-Q / Dock-Quit / Dock-unresponsive-timeout),
         * downgrade to NSTerminateCancel: post the event so any
         * Wine app that wants to react can, but don't make Cocoa
         * wait for our reply. The user can still close the bottle
         * via the launcher's TERM/INT (kill-bottle-procs.sh). */
        if (ret == NSTerminateLater
            && quitReason != kAELogOut
            && quitReason != kAEReallyLogOut
            && quitReason != kAEShowRestartDialog
            && quitReason != kAEShowShutdownDialog)
        {
            /* PROTON_AUTO_EXIT_ON_LAST_WINDOW=1: the user is explicitly
             * asking the game to exit via Dock-Quit / menu Cmd-Q. The
             * legacy NSTerminateCancel path refuses to exit, leaving
             * the user with no clean shutdown when in-game Quit hides
             * UI but doesn't drive ExitProcess (UE4-style: ABZU, Hades).
             * With the env opt-in, route the cancel through SIGTERM to
             * self: wine's signal handler runs the normal exit including
             * winecoreaudio's process_detach so the audio loop stops
             * and the process actually dies. Without the env, fall
             * through to the original cancel-only behaviour.
             * (Proton macOS) */
            const char *auto_exit = getenv("PROTON_AUTO_EXIT_ON_LAST_WINDOW");
            if (auto_exit && auto_exit[0] && auto_exit[0] != '0')
            {
                fprintf(stderr,
                        "winemac: kAEQuit (reason=%d) + PROTON_AUTO_EXIT_ON_LAST_WINDOW=1 - SIGTERM self (pid=%d)\n",
                        (int)quitReason, getpid());
                kill(getpid(), SIGTERM);
                ret = NSTerminateCancel;
            }
            else
            {
                fprintf(stderr,
                        "winemac: ignoring unsolicited kAEQuit (reason=%d) - returning NSTerminateCancel\n",
                        (int)quitReason);
                ret = NSTerminateCancel;
            }
        }

        return ret;
    }

    - (void)applicationWillBecomeActive:(NSNotification *)notification
    {
        macdrv_event* event = macdrv_create_event(APP_ACTIVATED, nil);
        event->deliver = 1;

        [eventQueuesLock lock];
        for (WineEventQueue* queue in eventQueues)
            [queue postEvent:event];
        [eventQueuesLock unlock];

        macdrv_release_event(event);
    }

    - (void)applicationWillResignActive:(NSNotification *)notification
    {
        [self adjustWindowLevels:NO];
    }

/***********************************************************************
 *              PerformRequest
 *
 * Run-loop-source perform callback.  Pull request blocks from the
 * array of queued requests and invoke them.
 */
static void PerformRequest(void *info)
{
@autoreleasepool
{
    WineApplicationController* controller = [WineApplicationController sharedController];

    for (;;)
    {
        @autoreleasepool
        {
            __block dispatch_block_t block;

            dispatch_sync(controller->requestsManipQueue, ^{
                if ([controller->requests count])
                {
                    block = (dispatch_block_t)[controller->requests[0] retain];
                    [controller->requests removeObjectAtIndex:0];
                }
                else
                    block = nil;
            });

            if (!block)
                break;

            block();
            [block release];
        }
    }
}
}

/***********************************************************************
 *              OnMainThreadAsync
 *
 * Run a block on the main thread asynchronously.
 */
void OnMainThreadAsync(dispatch_block_t block)
{
    WineApplicationController* controller = [WineApplicationController sharedController];

    block = [block copy];
    dispatch_sync(controller->requestsManipQueue, ^{
        [controller->requests addObject:block];
    });
    [block release];
    CFRunLoopSourceSignal(controller->requestSource);
    CFRunLoopWakeUp(CFRunLoopGetMain());
}

@end

/***********************************************************************
 *              LogError
 */
void LogError(const char* func, NSString* format, ...)
{
    va_list args;
    va_start(args, format);
    LogErrorv(func, format, args);
    va_end(args);
}

/***********************************************************************
 *              LogErrorv
 */
void LogErrorv(const char* func, NSString* format, va_list args)
{
@autoreleasepool
{
    NSString* message = [[NSString alloc] initWithFormat:format arguments:args];
    fprintf(stderr, "err:%s:%s", func, [message UTF8String]);
    [message release];
}
}

/***********************************************************************
 *              macdrv_window_rejected_focus
 *
 * Pass focus to the next window that hasn't already rejected this same
 * WINDOW_GOT_FOCUS event.
 */
void macdrv_window_rejected_focus(const macdrv_event *event)
{
    OnMainThread(^{
        [[WineApplicationController sharedController] windowRejectedFocusEvent:event];
    });
}

/***********************************************************************
 *              macdrv_get_input_source_info
 *
 * Returns the keyboard layout uchr data, keyboard type and input source.
 */
void macdrv_get_input_source_info(CFDataRef* uchr, CGEventSourceKeyboardType* keyboard_type, bool* is_iso, TISInputSourceRef* input_source)
{
    OnMainThread(^{
        TISInputSourceRef inputSourceLayout;

        inputSourceLayout = TISCopyCurrentKeyboardLayoutInputSource();
        if (inputSourceLayout)
        {
            CFDataRef data = TISGetInputSourceProperty(inputSourceLayout,
                                kTISPropertyUnicodeKeyLayoutData);
            *uchr = CFDataCreateCopy(NULL, data);
            CFRelease(inputSourceLayout);

            *keyboard_type = [WineApplicationController sharedController].keyboardType;
            *is_iso = (KBGetLayoutType(*keyboard_type) == kKeyboardISO);
            if (input_source)
                *input_source = TISCopyCurrentKeyboardInputSource();
        }
    });
}

/***********************************************************************
 *              macdrv_beep
 *
 * Play the beep sound configured by the user in System Preferences.
 */
void macdrv_beep(void)
{
    OnMainThreadAsync(^{
        NSBeep();
    });
}

/***********************************************************************
 *              macdrv_set_display_mode
 */
int macdrv_set_display_mode(CGDirectDisplayID displayID, CGDisplayModeRef display_mode)
{
    __block int ret;

    OnMainThread(^{
        ret = [[WineApplicationController sharedController] setMode:display_mode forDisplay:displayID];
    });

    return ret;
}

/***********************************************************************
 *              macdrv_set_cursor
 *
 * Set the cursor.
 *
 * If name is non-NULL, it is a selector for a class method on NSCursor
 * identifying the cursor to set.  In that case, frames is ignored.  If
 * name is NULL, then frames is used.
 *
 * frames is an array of dictionaries.  Each dictionary is a frame of
 * an animated cursor.  Under the key "image" is a CGImage for the
 * frame.  Under the key "duration" is a CFNumber time interval, in
 * seconds, for how long that frame is presented before proceeding to
 * the next frame.  Under the key "hotSpot" is a CFDictionary encoding a
 * CGPoint, to be decoded using CGPointMakeWithDictionaryRepresentation().
 * This is the hot spot, measured in pixels down and to the right of the
 * top-left corner of the image.
 *
 * If the array has exactly 1 element, the cursor is static, not
 * animated.  If frames is NULL or has 0 elements, the cursor is hidden.
 */
void macdrv_set_cursor(CFStringRef name, CFArrayRef frames)
{
    SEL sel;

    sel = NSSelectorFromString((NSString*)name);
    if (sel)
    {
        OnMainThreadAsync(^{
            WineApplicationController* controller = [WineApplicationController sharedController];
            [controller setCursorWithFrames:nil];
            controller.cursor = [NSCursor performSelector:sel];
            [controller unhideCursor];
        });
    }
    else
    {
        NSArray* nsframes = (NSArray*)frames;
        if ([nsframes count])
        {
            OnMainThreadAsync(^{
                [[WineApplicationController sharedController] setCursorWithFrames:nsframes];
            });
        }
        else
        {
            OnMainThreadAsync(^{
                WineApplicationController* controller = [WineApplicationController sharedController];
                [controller setCursorWithFrames:nil];
                [controller hideCursor];
            });
        }
    }
}

/***********************************************************************
 *              macdrv_get_cursor_position
 *
 * Obtains the current cursor position.  Returns zero on failure,
 * non-zero on success.
 */
int macdrv_get_cursor_position(CGPoint *pos)
{
    OnMainThread(^{
        NSPoint location = [NSEvent mouseLocation];
        location = [[WineApplicationController sharedController] flippedMouseLocation:location];
        *pos = cgpoint_win_from_mac(NSPointToCGPoint(location));
    });

    return TRUE;
}

/***********************************************************************
 *              macdrv_set_cursor_position
 *
 * Sets the cursor position without generating events.  Returns zero on
 * failure, non-zero on success.
 */
int macdrv_set_cursor_position(CGPoint pos)
{
    __block int ret;

    OnMainThread(^{
        ret = [[WineApplicationController sharedController] setCursorPosition:cgpoint_mac_from_win(pos)];
    });

    return ret;
}

/***********************************************************************
 *              macdrv_clip_cursor
 *
 * Sets the cursor cursor clipping rectangle.  If the rectangle is equal
 * to or larger than the whole desktop region, the cursor is unclipped.
 * Returns zero on failure, non-zero on success.
 */
int macdrv_clip_cursor(CGRect r)
{
    __block int ret;

    OnMainThread(^{
        WineApplicationController* controller = [WineApplicationController sharedController];
        BOOL clipping = FALSE;
        CGRect rect = r;

        if (!CGRectIsInfinite(rect))
            rect = cgrect_mac_from_win(rect);

        if (!CGRectIsInfinite(rect))
        {
            NSRect nsrect = NSRectFromCGRect(rect);
            NSScreen* screen;

            /* Convert the rectangle from top-down coords to bottom-up. */
            [controller flipRect:&nsrect];

            clipping = FALSE;
            for (screen in [NSScreen screens])
            {
                if (!NSContainsRect(nsrect, [screen frame]))
                {
                    clipping = TRUE;
                    break;
                }
            }
        }

        if (clipping)
            ret = [controller startClippingCursor:rect];
        else
            ret = [controller stopClippingCursor];
    });

    return ret;
}

/***********************************************************************
 *              macdrv_set_application_icon
 *
 * Set the application icon.  The images array contains CGImages.  If
 * there are more than one, then they represent different sizes or
 * color depths from the icon resource.  If images is NULL or empty,
 * restores the default application image.
 */
void macdrv_set_application_icon(CFArrayRef images)
{
    NSArray* imageArray = (NSArray*)images;

    OnMainThreadAsync(^{
        [[WineApplicationController sharedController] setApplicationIconFromCGImageArray:imageArray];
    });
}

/***********************************************************************
 *              macdrv_quit_reply
 */
void macdrv_quit_reply(int reply)
{
    OnMainThread(^{
        [NSApp replyToApplicationShouldTerminate:reply];
    });
}

/***********************************************************************
 *              macdrv_using_input_method
 */
bool macdrv_using_input_method(void)
{
    __block bool ret;

    OnMainThread(^{
        ret = [[WineApplicationController sharedController] inputSourceIsInputMethod];
    });

    return ret;
}

/***********************************************************************
 *              macdrv_set_mouse_capture_window
 */
void macdrv_set_mouse_capture_window(macdrv_window window, int move_size)
{
    WineWindow* w = (WineWindow*)window;

    [w.queue discardEventsMatchingMask:event_mask_for_type(RELEASE_CAPTURE) forWindow:w];

    OnMainThread(^{
        WineApplicationController* controller = [WineApplicationController sharedController];
        controller.mouseCaptureIsMoveSize = (w && move_size) ? YES : NO;
        [controller setMouseCaptureWindow:w];
    });
}

const CFStringRef macdrv_input_source_input_key = CFSTR("input");
const CFStringRef macdrv_input_source_type_key = CFSTR("type");
const CFStringRef macdrv_input_source_lang_key = CFSTR("lang");

/***********************************************************************
 *              macdrv_create_input_source_list
 */
CFArrayRef macdrv_create_input_source_list(void)
{
    CFMutableArrayRef ret = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);

    OnMainThread(^{
        CFArrayRef input_list;
        CFDictionaryRef filter_dict;
        const void *filter_keys[2] = { kTISPropertyInputSourceCategory, kTISPropertyInputSourceIsSelectCapable };
        const void *filter_values[2] = { kTISCategoryKeyboardInputSource, kCFBooleanTrue };
        int i;

        filter_dict = CFDictionaryCreate(NULL, filter_keys, filter_values, sizeof(filter_keys)/sizeof(filter_keys[0]),
                                         &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        input_list = TISCreateInputSourceList(filter_dict, false);

        for (i = 0; i < CFArrayGetCount(input_list); i++)
        {
            TISInputSourceRef input = (TISInputSourceRef)CFArrayGetValueAtIndex(input_list, i);
            CFArrayRef source_langs = TISGetInputSourceProperty(input, kTISPropertyInputSourceLanguages);
            CFDictionaryRef entry;
            const void *input_keys[3] = { macdrv_input_source_input_key,
                                          macdrv_input_source_type_key,
                                          macdrv_input_source_lang_key };
            const void *input_values[3];

            input_values[0] = input;
            input_values[1] = TISGetInputSourceProperty(input, kTISPropertyInputSourceType);
            input_values[2] = CFArrayGetValueAtIndex(source_langs, 0);

            entry = CFDictionaryCreate(NULL, input_keys, input_values, sizeof(input_keys) / sizeof(input_keys[0]),
                                       &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

            CFArrayAppendValue(ret, entry);
            CFRelease(entry);
        }
        CFRelease(input_list);
        CFRelease(filter_dict);
    });

    return ret;
}

bool macdrv_select_input_source(TISInputSourceRef input_source)
{
    __block bool ret = false;

    OnMainThread(^{
        ret = (TISSelectInputSource(input_source) == noErr);
    });

    return ret;
}

void macdrv_set_cocoa_retina_mode(bool new_mode)
{
    OnMainThread(^{
        [[WineApplicationController sharedController] setRetinaMode:new_mode];
    });
}

bool macdrv_is_any_wine_window_visible(void)
{
    __block bool ret = false;

    OnMainThread(^{
        ret = [[WineApplicationController sharedController] isAnyWineWindowVisible];
    });

    return ret;
}
