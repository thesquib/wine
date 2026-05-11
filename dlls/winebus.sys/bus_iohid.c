/*  Bus like function for mac HID devices
 *
 * Copyright 2016 CodeWeavers, Aric Stewart
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

#if 0
#pragma makedep unix
#endif

#include "config.h"

#include <stdarg.h>
#include <sys/types.h>

#ifdef __APPLE__
#define DWORD UInt32
#define LPDWORD UInt32*
#define LONG SInt32
#define LPLONG SInt32*
#define E_PENDING __carbon_E_PENDING
#define ULONG __carbon_ULONG
#define E_INVALIDARG __carbon_E_INVALIDARG
#define E_OUTOFMEMORY __carbon_E_OUTOFMEMORY
#define E_HANDLE __carbon_E_HANDLE
#define E_ACCESSDENIED __carbon_E_ACCESSDENIED
#define E_UNEXPECTED __carbon_E_UNEXPECTED
#define E_FAIL __carbon_E_FAIL
#define E_ABORT __carbon_E_ABORT
#define E_POINTER __carbon_E_POINTER
#define E_NOINTERFACE __carbon_E_NOINTERFACE
#define E_NOTIMPL __carbon_E_NOTIMPL
#define S_FALSE __carbon_S_FALSE
#define S_OK __carbon_S_OK
#define HRESULT_FACILITY __carbon_HRESULT_FACILITY
#define IS_ERROR __carbon_IS_ERROR
#define FAILED __carbon_FAILED
#define SUCCEEDED __carbon_SUCCEEDED
#define MAKE_HRESULT __carbon_MAKE_HRESULT
#define HRESULT __carbon_HRESULT
#define STDMETHODCALLTYPE __carbon_STDMETHODCALLTYPE
#define PAGE_SHIFT __carbon_PAGE_SHIFT
#include <IOKit/IOKitLib.h>
#include <IOKit/hid/IOHIDLib.h>
#undef ULONG
#undef E_INVALIDARG
#undef E_OUTOFMEMORY
#undef E_HANDLE
#undef E_ACCESSDENIED
#undef E_UNEXPECTED
#undef E_FAIL
#undef E_ABORT
#undef E_POINTER
#undef E_NOINTERFACE
#undef E_NOTIMPL
#undef S_FALSE
#undef S_OK
#undef HRESULT_FACILITY
#undef IS_ERROR
#undef FAILED
#undef SUCCEEDED
#undef MAKE_HRESULT
#undef HRESULT
#undef STDMETHODCALLTYPE
#undef DWORD
#undef LPDWORD
#undef LONG
#undef LPLONG
#undef E_PENDING
#undef PAGE_SHIFT
#endif /* __APPLE__ */

#include <pthread.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "winioctl.h"
#include "ddk/wdm.h"
#include "ddk/hidtypes.h"
#include "wine/debug.h"

#include "unix_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(hid);
#ifdef __APPLE__

static pthread_mutex_t iohid_cs = PTHREAD_MUTEX_INITIALIZER;

static IOHIDManagerRef hid_manager;
static CFRunLoopRef run_loop;
static struct list event_queue = LIST_INIT(event_queue);
static struct list device_list = LIST_INIT(device_list);
static const struct bus_options *options;
static unsigned int matched_device_count;

static int proton_hid_feed_enabled(void)
{
    static int cached = -1;
    if (cached < 0)
    {
        const char *v = getenv("PROTON_HID_FEED");
        cached = (v && *v && strcmp(v, "0") != 0) ? 1 : 0;
    }
    return cached;
}

static void proton_hid_feed_permission_check(CFRunLoopTimerRef timer, void *info)
{
    /* This callback fires on the feed thread - use fprintf, not ERR. */
    if (matched_device_count == 0)
    {
        fprintf(stderr, "winebus:[HID-FEED] WARNING: 0 HID devices matched after 5s. "
                "Likely missing Input Monitoring permission for the wine binary. "
                "System Settings -> Privacy & Security -> Input Monitoring.\n");
    }
    else
    {
        fprintf(stderr, "winebus:[HID-FEED] %u HID devices matched after 5s\n",
                matched_device_count);
    }
    fflush(stderr);
}

/* Phase C: dedicated feed-thread state. Only used when
 * proton_hid_feed_enabled() is true; otherwise zero behavior change. */
static pthread_t hid_feed_thread;
static int hid_feed_thread_running;
static CFRunLoopRef hid_feed_run_loop;
static pthread_mutex_t hid_feed_start_cs = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t hid_feed_start_cv = PTHREAD_COND_INITIALIZER;

/* Helper: take iohid_cs around a queue push when we're in feed-thread
 * mode. In env-off mode, callbacks already fire on the wait thread
 * with iohid_cs held by CFRunLoopRunInMode caller, so taking the lock
 * again would deadlock (mutex is non-recursive). */
static inline void iohid_feed_lock(void)
{
    if (proton_hid_feed_enabled() && hid_feed_thread_running)
        pthread_mutex_lock(&iohid_cs);
}

static inline void iohid_feed_unlock(void)
{
    if (proton_hid_feed_enabled() && hid_feed_thread_running)
        pthread_mutex_unlock(&iohid_cs);
}

struct iohid_device
{
    struct unix_device unix_device;
    IOHIDDeviceRef device;
    uint8_t *buffer;
};

static inline struct iohid_device *impl_from_unix_device(struct unix_device *iface)
{
    return CONTAINING_RECORD(iface, struct iohid_device, unix_device);
}

static struct iohid_device *find_device_from_iohid(IOHIDDeviceRef IOHIDDevice)
{
    struct iohid_device *impl;

    LIST_FOR_EACH_ENTRY(impl, &device_list, struct iohid_device, unix_device.entry)
        if (impl->device == IOHIDDevice) return impl;

    return NULL;
}

static void CFStringToWSTR(CFStringRef cstr, LPWSTR wstr, int length)
{
    int len = min(CFStringGetLength(cstr), length - 1);
    CFStringGetCharacters(cstr, CFRangeMake(0, len), (UniChar*)wstr);
    wstr[len] = 0;
}

static DWORD CFNumberToDWORD(CFNumberRef num)
{
    int dwNum = 0;
    if (num)
        CFNumberGetValue(num, kCFNumberIntType, &dwNum);
    return dwNum;
}

static void handle_IOHIDDeviceIOHIDReportCallback(void *context,
        IOReturn result, void *sender, IOHIDReportType type,
        uint32_t reportID, uint8_t *report, CFIndex report_length)
{
    struct unix_device *iface = (struct unix_device *)context;

    /* PROTON_HID_FEED_REPORT_TRACE=1: dump raw HID report bytes per
     * event with throttle. Helps diagnose mouse delta sign / endian
     * issues. Only logs every Nth event to avoid log explosion at
     * 120-1000 Hz polling rates. Use raw fprintf - this is on the
     * feed thread (no wine TLS). */
    {
        static int trace_cached = -1;
        static unsigned long trace_n = 0;
        if (trace_cached < 0)
        {
            const char *v = getenv("PROTON_HID_FEED_REPORT_TRACE");
            trace_cached = (v && *v && strcmp(v, "0") != 0) ? 1 : 0;
        }
        if (trace_cached)
        {
            unsigned long n = ++trace_n;
            if (n <= 8 || (n % 60) == 0)
            {
                int i;
                fprintf(stderr, "winebus:[HID-REPORT #%lu] iface=%p type=%d id=%u len=%ld bytes=",
                        n, iface, (int)type, reportID, (long)report_length);
                for (i = 0; i < report_length && i < 16; i++)
                    fprintf(stderr, "%02x ", report[i]);
                if (report_length > 16) fprintf(stderr, "...");
                fprintf(stderr, "\n");
                fflush(stderr);
            }
        }
    }

    iohid_feed_lock();
    bus_event_queue_input_report(&event_queue, iface, report, report_length);
    iohid_feed_unlock();
}

static void iohid_device_destroy(struct unix_device *iface)
{
}

static NTSTATUS iohid_device_start(struct unix_device *iface)
{
    DWORD length;
    struct iohid_device *impl = impl_from_unix_device(iface);
    CFNumberRef num;

    num = IOHIDDeviceGetProperty(impl->device, CFSTR(kIOHIDMaxInputReportSizeKey));
    length = CFNumberToDWORD(num);
    impl->buffer = malloc(length);

    IOHIDDeviceRegisterInputReportCallback(impl->device, impl->buffer, length, handle_IOHIDDeviceIOHIDReportCallback, iface);

    /* PROTON_HID_FEED diagnostic: log when hidclass actually starts
     * a device, registering its input report callback. If devices
     * get matched (matched device log) but never started (no log
     * here), hidclass isn't consuming our bus_events. Use raw
     * fprintf because this can run on either thread. */
    if (proton_hid_feed_enabled())
    {
        fprintf(stderr, "winebus:[HID-FEED] iohid_device_start iface=%p buffer_size=%u\n",
                iface, (unsigned)length);
        fflush(stderr);
    }
    return STATUS_SUCCESS;
}

static void iohid_device_stop(struct unix_device *iface)
{
    struct iohid_device *impl = impl_from_unix_device(iface);

    IOHIDDeviceRegisterInputReportCallback(impl->device, NULL, 0, NULL, NULL);

    pthread_mutex_lock(&iohid_cs);
    list_remove(&impl->unix_device.entry);
    pthread_mutex_unlock(&iohid_cs);
}

static NTSTATUS iohid_device_get_report_descriptor(struct unix_device *iface, BYTE *buffer,
                                                   UINT length, UINT *out_length)
{
    struct iohid_device *impl = impl_from_unix_device(iface);
    CFDataRef data = IOHIDDeviceGetProperty(impl->device, CFSTR(kIOHIDReportDescriptorKey));
    int data_length = CFDataGetLength(data);
    const UInt8 *ptr;

    *out_length = data_length;
    if (length < data_length)
        return STATUS_BUFFER_TOO_SMALL;

    ptr = CFDataGetBytePtr(data);
    memcpy(buffer, ptr, data_length);
    return STATUS_SUCCESS;
}

static void iohid_device_set_output_report(struct unix_device *iface, HID_XFER_PACKET *packet, IO_STATUS_BLOCK *io)
{
    IOReturn result;
    struct iohid_device *impl = impl_from_unix_device(iface);
    result = IOHIDDeviceSetReport(impl->device, kIOHIDReportTypeOutput, packet->reportId,
                                  packet->reportBuffer, packet->reportBufferLen);
    if (result == kIOReturnSuccess)
    {
        io->Information = packet->reportBufferLen;
        io->Status = STATUS_SUCCESS;
    }
    else
    {
        io->Information = 0;
        io->Status = STATUS_UNSUCCESSFUL;
    }
}

static void iohid_device_get_feature_report(struct unix_device *iface, HID_XFER_PACKET *packet, IO_STATUS_BLOCK *io)
{
    IOReturn ret;
    CFIndex report_length = packet->reportBufferLen;
    struct iohid_device *impl = impl_from_unix_device(iface);

    ret = IOHIDDeviceGetReport(impl->device, kIOHIDReportTypeFeature, packet->reportId,
                               packet->reportBuffer, &report_length);
    if (ret == kIOReturnSuccess)
    {
        io->Information = report_length;
        io->Status = STATUS_SUCCESS;
    }
    else
    {
        io->Information = 0;
        io->Status = STATUS_UNSUCCESSFUL;
    }
}

static void iohid_device_set_feature_report(struct unix_device *iface, HID_XFER_PACKET *packet, IO_STATUS_BLOCK *io)
{
    IOReturn result;
    struct iohid_device *impl = impl_from_unix_device(iface);

    result = IOHIDDeviceSetReport(impl->device, kIOHIDReportTypeFeature, packet->reportId,
                                  packet->reportBuffer, packet->reportBufferLen);
    if (result == kIOReturnSuccess)
    {
        io->Information = packet->reportBufferLen;
        io->Status = STATUS_SUCCESS;
    }
    else
    {
        io->Information = 0;
        io->Status = STATUS_UNSUCCESSFUL;
    }
}

static const struct raw_device_vtbl iohid_device_vtbl =
{
    iohid_device_destroy,
    iohid_device_start,
    iohid_device_stop,
    iohid_device_get_report_descriptor,
    iohid_device_set_output_report,
    iohid_device_get_feature_report,
    iohid_device_set_feature_report,
};

static void handle_DeviceMatchingCallback(void *context, IOReturn result, void *sender, IOHIDDeviceRef IOHIDDevice)
{
    struct device_desc desc =
    {
        .input = -1, .is_hidraw = TRUE,
        .serialnumber = {'0','0','0','0',0},
    };
    struct iohid_device *impl;
    USAGE_AND_PAGE usages;
    CFStringRef str;

    usages.UsagePage = CFNumberToDWORD(IOHIDDeviceGetProperty(IOHIDDevice, CFSTR(kIOHIDPrimaryUsagePageKey)));
    usages.Usage = CFNumberToDWORD(IOHIDDeviceGetProperty(IOHIDDevice, CFSTR(kIOHIDPrimaryUsageKey)));

    desc.vid = CFNumberToDWORD(IOHIDDeviceGetProperty(IOHIDDevice, CFSTR(kIOHIDVendorIDKey)));
    desc.pid = CFNumberToDWORD(IOHIDDeviceGetProperty(IOHIDDevice, CFSTR(kIOHIDProductIDKey)));
    desc.version = CFNumberToDWORD(IOHIDDeviceGetProperty(IOHIDDevice, CFSTR(kIOHIDVersionNumberKey)));
    desc.uid = CFNumberToDWORD(IOHIDDeviceGetProperty(IOHIDDevice, CFSTR(kIOHIDLocationIDKey)));

    if ((str = IOHIDDeviceGetProperty(IOHIDDevice, CFSTR(kIOHIDTransportKey))))
    {
        if (!CFStringCompare(str, CFSTR(kIOHIDTransportBluetoothValue), 0) ||
                            !CFStringCompare(str, CFSTR(kIOHIDTransportBluetoothLowEnergyValue), 0))
            desc.bus_type = BUS_TYPE_BLUETOOTH;
        else if (!CFStringCompare(str, CFSTR(kIOHIDTransportUSBValue), 0))
            desc.bus_type = BUS_TYPE_USB;
    }

    if (usages.UsagePage != HID_USAGE_PAGE_GENERIC ||
        !(usages.Usage == HID_USAGE_GENERIC_JOYSTICK ||
          usages.Usage == HID_USAGE_GENERIC_GAMEPAD ||
          (proton_hid_feed_enabled() &&
           (usages.Usage == HID_USAGE_GENERIC_MOUSE ||
            usages.Usage == HID_USAGE_GENERIC_KEYBOARD))))
    {
        /* winebus isn't currently meant to handle anything but these, and
         * opening keyboards, mice, or the Touch Bar on older MacBooks triggers
         * a permissions dialog for input monitoring.
         * When PROTON_HID_FEED=1, mice and keyboards are allowed through.
         * The user must grant macOS Input Monitoring permission on first
         * run; without it IOHIDManager silently never matches.
         */
        if (proton_hid_feed_enabled())
        {
            fprintf(stderr, "winebus:[HID-FEED] ignoring device vid=%04x pid=%04x usage_page=%u usage=%u (not a joystick/gamepad/mouse/keyboard)\n",
                    desc.vid, desc.pid, usages.UsagePage, usages.Usage);
            fflush(stderr);
        }
        else WARN("Ignoring HID device %p (vid %04x, pid %04x): not a joystick or gamepad\n", IOHIDDevice, desc.vid, desc.pid);
        return;
    }

    if (IOHIDDeviceOpen(IOHIDDevice, 0) != kIOReturnSuccess)
    {
        if (proton_hid_feed_enabled())
        {
            fprintf(stderr, "winebus:[HID-FEED] IOHIDDeviceOpen failed for vid=%04x pid=%04x\n", desc.vid, desc.pid);
            fflush(stderr);
        }
        else ERR("Failed to open HID device %p (vid %04x, pid %04x)\n", IOHIDDevice, desc.vid, desc.pid);
        return;
    }
    IOHIDDeviceScheduleWithRunLoop(IOHIDDevice, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);

    str = IOHIDDeviceGetProperty(IOHIDDevice, CFSTR(kIOHIDManufacturerKey));
    if (str) CFStringToWSTR(str, desc.manufacturer, ARRAY_SIZE(desc.manufacturer));
    str = IOHIDDeviceGetProperty(IOHIDDevice, CFSTR(kIOHIDProductKey));
    if (str) CFStringToWSTR(str, desc.product, ARRAY_SIZE(desc.product));
    str = IOHIDDeviceGetProperty(IOHIDDevice, CFSTR(kIOHIDSerialNumberKey));
    if (str) CFStringToWSTR(str, desc.serialnumber, ARRAY_SIZE(desc.serialnumber));

    matched_device_count++;
    if (proton_hid_feed_enabled())
    {
        /* Use raw fprintf - this callback fires on the feed thread which
         * has no wine TLS, so ERR/TRACE/WARN macros crash silently. */
        fprintf(stderr, "winebus:[HID-FEED] matched device vid=%04x pid=%04x usage=%u count=%u\n",
                desc.vid, desc.pid, usages.Usage, matched_device_count);
        fflush(stderr);
        /* Mice and keyboards must go through the non-hidraw bus path
         * so bus_main_thread routes them to bus_create_hid_device.
         * The hidraw path requires PROTON_ENABLE_HIDRAW per-device and
         * is_hidraw_enabled() rejects mice/keyboards by default. */
        if (usages.UsagePage == HID_USAGE_PAGE_GENERIC &&
            (usages.Usage == HID_USAGE_GENERIC_MOUSE ||
             usages.Usage == HID_USAGE_GENERIC_KEYBOARD))
            desc.is_hidraw = FALSE;
    }

    if (IOHIDDeviceConformsTo(IOHIDDevice, kHIDPage_GenericDesktop, kHIDUsage_GD_GamePad) ||
       IOHIDDeviceConformsTo(IOHIDDevice, kHIDPage_GenericDesktop, kHIDUsage_GD_Joystick))
    {
        if (is_xbox_gamepad(desc.vid, desc.pid))
            desc.is_gamepad = TRUE;
    }

    if (proton_hid_feed_enabled())
    {
        fprintf(stderr, "winebus:[HID-FEED] queuing device for hidclass dev=%p vid=%04x pid=%04x usage=%u\n",
                IOHIDDevice, desc.vid, desc.pid, usages.Usage);
        fflush(stderr);
    }
    else TRACE("dev %p, desc %s.\n", IOHIDDevice, debugstr_device_desc(&desc));

    if (!(impl = raw_device_create(&iohid_device_vtbl, sizeof(struct iohid_device))))
    {
        if (proton_hid_feed_enabled())
        {
            fprintf(stderr, "winebus:[HID-FEED] raw_device_create FAILED dev=%p\n", IOHIDDevice);
            fflush(stderr);
        }
        return;
    }
    list_add_tail(&device_list, &impl->unix_device.entry);
    impl->device = IOHIDDevice;
    impl->buffer = NULL;

    iohid_feed_lock();
    bus_event_queue_device_created(&event_queue, &impl->unix_device, &desc);
    iohid_feed_unlock();

    if (proton_hid_feed_enabled())
    {
        fprintf(stderr, "winebus:[HID-FEED] queued device-created event for dev=%p vid=%04x pid=%04x\n",
                IOHIDDevice, desc.vid, desc.pid);
        fflush(stderr);
    }
}

static void handle_RemovalCallback(void *context, IOReturn result, void *sender, IOHIDDeviceRef IOHIDDevice)
{
    struct iohid_device *impl;

    TRACE("OS/X IOHID Device Removed %p\n", IOHIDDevice);
    IOHIDDeviceRegisterInputReportCallback(IOHIDDevice, NULL, 0, NULL, NULL);
    /* Note: Yes, we leak the buffer. But according to research there is no
             safe way to deallocate that buffer. */
    IOHIDDeviceUnscheduleFromRunLoop(IOHIDDevice, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
    IOHIDDeviceClose(IOHIDDevice, 0);

    impl = find_device_from_iohid(IOHIDDevice);
    if (impl)
    {
        iohid_feed_lock();
        bus_event_queue_device_removed(&event_queue, &impl->unix_device);
        iohid_feed_unlock();
    }
    else WARN("failed to find device for iohid device %p\n", IOHIDDevice);
}

static void *hid_feed_thread_func(void *arg)
{
    CFRunLoopRef loop = CFRunLoopGetCurrent();
    CFRunLoopTimerRef perm_timer;
    IOReturn open_ret;

    /* Wine's ERR/TRACE/WARN macros use per-thread TLS that is only
     * set up for wine-managed threads. A raw pthread_create()d thread
     * has no wine TLS, so calling them from here crashes silently.
     * Use raw fprintf for ALL logging on this thread; never call
     * a wine-debug-channel macro. The matching/removal callbacks
     * (handle_DeviceMatchingCallback, handle_RemovalCallback) also
     * fire on this thread - their existing ERR/TRACE/WARN have been
     * gated to fprintf when proton_hid_feed_enabled(). */
    pthread_mutex_lock(&hid_feed_start_cs);
    hid_feed_run_loop = loop;
    IOHIDManagerScheduleWithRunLoop(hid_manager, loop, kCFRunLoopDefaultMode);
    open_ret = IOHIDManagerOpen(hid_manager, kIOHIDOptionsTypeNone);
    /* Schedule the 5s permission-check timer on THIS thread's runloop
     * so it actually fires (run_loop on the init thread doesn't
     * iterate after init returns). */
    perm_timer = CFRunLoopTimerCreate(kCFAllocatorDefault,
                                      CFAbsoluteTimeGetCurrent() + 5.0, 0, 0, 0,
                                      proton_hid_feed_permission_check, NULL);
    if (perm_timer)
    {
        CFRunLoopAddTimer(loop, perm_timer, kCFRunLoopDefaultMode);
        CFRelease(perm_timer);
    }
    hid_feed_thread_running = 1;
    pthread_cond_signal(&hid_feed_start_cv);
    pthread_mutex_unlock(&hid_feed_start_cs);

    if (open_ret != kIOReturnSuccess)
        fprintf(stderr, "winebus:[HID-FEED] IOHIDManagerOpen failed on feed thread, ret=0x%x\n", open_ret);
    fprintf(stderr, "winebus:[HID-FEED] feed thread started, runloop=%p, open_ret=0x%x\n", loop, open_ret);
    fflush(stderr);

    CFRunLoopRun();

    fprintf(stderr, "winebus:[HID-FEED] feed thread exiting\n");
    fflush(stderr);

    IOHIDManagerUnscheduleFromRunLoop(hid_manager, loop, kCFRunLoopDefaultMode);
    return NULL;
}

static void start_hid_feed_thread(void)
{
    int err;
    pthread_mutex_lock(&hid_feed_start_cs);
    err = pthread_create(&hid_feed_thread, NULL, hid_feed_thread_func, NULL);
    if (err)
    {
        ERR("winebus:[HID-FEED] pthread_create failed: %d\n", err);
        pthread_mutex_unlock(&hid_feed_start_cs);
        return;
    }
    /* Wait until the feed thread captures its runloop and signals. */
    while (!hid_feed_thread_running)
        pthread_cond_wait(&hid_feed_start_cv, &hid_feed_start_cs);
    pthread_mutex_unlock(&hid_feed_start_cs);
    ERR("winebus:[HID-FEED] feed thread handshake complete, runloop=%p\n", hid_feed_run_loop);
}

NTSTATUS iohid_bus_init(void *args)
{
    TRACE("args %p\n", args);

    options = args;

    if (!(hid_manager = IOHIDManagerCreate(kCFAllocatorDefault, 0L)))
    {
        ERR("IOHID manager creation failed\n");
        return STATUS_UNSUCCESSFUL;
    }

    run_loop = CFRunLoopGetCurrent();

    if (proton_hid_feed_enabled())
    {
        ERR("winebus:[HID-FEED] PROTON_HID_FEED=1, mice and keyboards will be matched "
            "(Input Monitoring permission required)\n");
        /* The 5s permission-check timer is now added inside the feed
         * thread on its own runloop - run_loop here doesn't iterate so
         * a timer added to it would never fire. See hid_feed_thread_func. */
    }

    IOHIDManagerSetDeviceMatching(hid_manager, NULL);
    IOHIDManagerRegisterDeviceMatchingCallback(hid_manager, handle_DeviceMatchingCallback, NULL);
    IOHIDManagerRegisterDeviceRemovalCallback(hid_manager, handle_RemovalCallback, NULL);

    if (proton_hid_feed_enabled())
    {
        /* Defer IOHIDManagerScheduleWithRunLoop and IOHIDManagerOpen
         * to the feed thread, which owns its own runloop and pumps
         * it continuously. The wait-thread runloop never iterates
         * IOHIDManager events in this mode. */
        start_hid_feed_thread();
    }
    else
    {
        IOHIDManagerScheduleWithRunLoop(hid_manager, run_loop, kCFRunLoopDefaultMode);
    }

    return STATUS_SUCCESS;
}

NTSTATUS iohid_bus_wait(void *args)
{
    struct bus_event *result = args;
    CFRunLoopRunResult ret;

    /* cleanup previously returned event */
    bus_event_cleanup(result);

    do
    {
        /* In feed-thread mode the queue is populated by the feed
         * thread; pop without holding iohid_cs across the long
         * runloop sleep so the feed thread can keep pushing. The
         * pop itself takes iohid_cs briefly to serialize against
         * concurrent push. */
        if (proton_hid_feed_enabled() && hid_feed_thread_running)
        {
            BOOL got;
            pthread_mutex_lock(&iohid_cs);
            got = bus_event_queue_pop(&event_queue, result);
            pthread_mutex_unlock(&iohid_cs);
            if (got) return STATUS_PENDING;
            /* Sleep 1ms when queue is empty. Matches 1000Hz mouse
             * polling rate so we don't drop motion events. Higher
             * sleep values (e.g. 100ms = 10Hz) caused visible mouse
             * stutter because real mice deliver 125-1000 events/sec
             * but the consumer only ran ~10x/sec, so most events
             * coalesced or sat in the queue. */
            usleep(1000);
            ret = kCFRunLoopRunTimedOut;
            continue;
        }

        if (bus_event_queue_pop(&event_queue, result)) return STATUS_PENDING;
        pthread_mutex_lock(&iohid_cs);
        ret = CFRunLoopRunInMode(kCFRunLoopDefaultMode, 10, TRUE);
        pthread_mutex_unlock(&iohid_cs);
    } while (ret != kCFRunLoopRunStopped);

    TRACE("IOHID main loop exiting\n");
    bus_event_queue_destroy(&event_queue);
    IOHIDManagerRegisterDeviceMatchingCallback(hid_manager, NULL, NULL);
    IOHIDManagerRegisterDeviceRemovalCallback(hid_manager, NULL, NULL);
    CFRelease(hid_manager);
    return STATUS_SUCCESS;
}

NTSTATUS iohid_bus_stop(void *args)
{
    if (hid_feed_thread_running)
    {
        ERR("winebus:[HID-FEED] stopping feed thread\n");
        if (hid_feed_run_loop) CFRunLoopStop(hid_feed_run_loop);
        pthread_join(hid_feed_thread, NULL);
        hid_feed_thread_running = 0;
        hid_feed_run_loop = NULL;
    }

    if (!run_loop) return STATUS_SUCCESS;

    if (!proton_hid_feed_enabled())
        IOHIDManagerUnscheduleFromRunLoop(hid_manager, run_loop, kCFRunLoopDefaultMode);
    CFRunLoopStop(run_loop);
    return STATUS_SUCCESS;
}

#else

NTSTATUS iohid_bus_init(void *args)
{
    WARN("IOHID support not compiled in!\n");
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS iohid_bus_wait(void *args)
{
    WARN("IOHID support not compiled in!\n");
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS iohid_bus_stop(void *args)
{
    WARN("IOHID support not compiled in!\n");
    return STATUS_NOT_IMPLEMENTED;
}

#endif /* __APPLE__ */
