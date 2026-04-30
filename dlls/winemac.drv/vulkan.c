/* Mac Driver Vulkan implementation
 *
 * Copyright 2017 Roderick Colenbrander
 * Copyright 2018 Andrew Eikum for CodeWeavers
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

/* NOTE: If making changes here, consider whether they should be reflected in
 * the other drivers. */

#if 0
#pragma makedep unix
#endif

#include "config.h"

#include <stdarg.h>
#include <stdio.h>
#include <dlfcn.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "macdrv.h"
#include "wine/debug.h"

#include "wine/vulkan.h"
#include "wine/vulkan_driver.h"

WINE_DEFAULT_DEBUG_CHANNEL(vulkan);

static const struct vulkan_driver_funcs macdrv_vulkan_driver_funcs;

/* Strategy E.1-vulkan - surface_update bypasses our broadcast on the very
 * first call from inside macdrv_client_surface_create because metal_view
 * is set AFTER that call returns. Trigger an explicit re-update at the
 * tail of vulkan_surface_create so the broadcast fires once the layer is
 * known and the swapchain hasn't yet been built. */
extern void macdrv_broadcast_vulkan_layer_host_request(void *hwnd, void *metal_layer);

static VkResult macdrv_vulkan_surface_create(HWND hwnd, BOOL raw, const struct vulkan_instance *instance,
                                             VkSurfaceKHR *handle, struct client_surface **client)
{
    VkResult res;
    struct macdrv_client_surface *surface;

    TRACE("%p %p %p %p\n", hwnd, instance, handle, client);

    /* Bug (Proton macOS) 2026-04-29 diagnostic: pinpoint which step in
     * surface creation is faulting (intermittent UNIX_CALL 0xc0000005).
     * Patch 0010 already NULL-checks `client_surface_create`; the fault
     * must be in a later deref. */
    fprintf(stderr, "winemac:VK surface_create ENTER hwnd=%p instance=%p handle=%p\n",
            hwnd, instance, handle);

    if (!(surface = macdrv_client_surface_create(hwnd))) {
        fprintf(stderr, "winemac:VK surface_create FAIL@1 macdrv_client_surface_create=NULL hwnd=%p\n", hwnd);
        return VK_ERROR_OUT_OF_HOST_MEMORY;
    }
    fprintf(stderr, "winemac:VK surface_create STEP1 surface=%p cocoa_view=%p\n",
            surface, surface ? surface->cocoa_view : NULL);

    if (!(surface->metal_device = macdrv_create_metal_device())) {
        fprintf(stderr, "winemac:VK surface_create FAIL@2 macdrv_create_metal_device=NULL\n");
        goto err;
    }
    fprintf(stderr, "winemac:VK surface_create STEP2 metal_device=%p\n", surface->metal_device);

    if (!(surface->metal_view = macdrv_view_create_metal_view(surface->cocoa_view, surface->metal_device))) {
        fprintf(stderr, "winemac:VK surface_create FAIL@3 macdrv_view_create_metal_view=NULL cocoa_view=%p device=%p\n",
                surface->cocoa_view, surface->metal_device);
        goto err;
    }
    fprintf(stderr, "winemac:VK surface_create STEP3 metal_view=%p\n", surface->metal_view);

    if (instance->p_vkCreateMetalSurfaceEXT)
    {
        VkMetalSurfaceCreateInfoEXT create_info_host;
        void *metal_layer;
        void *saved_delegate;

        create_info_host.sType = VK_STRUCTURE_TYPE_METAL_SURFACE_CREATE_INFO_EXT;
        create_info_host.pNext = NULL;
        create_info_host.flags = 0; /* reserved */
        metal_layer = (void *)macdrv_view_get_metal_layer(surface->metal_view);
        fprintf(stderr, "winemac:VK surface_create STEP4 metal_layer=%p (from metal_view=%p)\n",
                metal_layer, surface->metal_view);
        create_info_host.pLayer = metal_layer;

        /* Mac-port-26.2: temporarily clear the layer's delegate so MoltenVK's
         * MVKSurface::initLayer takes the early-return path and skips its
         * `addObserver:forKeyPath:@"layer"` KVO registration. macOS 26's
         * Foundation throws an Obj-C exception on that registration which
         * unwinds through the Wine syscall trampoline as a non-zero NTSTATUS,
         * tripping the assertion in loader_thunks.c:3759. Delegate restored
         * after the create call so winemac.drv's normal view tracking is
         * undisturbed. */
        saved_delegate = macdrv_save_metal_layer_delegate(metal_layer);
        fprintf(stderr, "winemac:VK surface_create STEP5 saved_delegate=%p, calling p_vkCreateMetalSurfaceEXT\n",
                saved_delegate);

        res = instance->p_vkCreateMetalSurfaceEXT(instance->host.instance, &create_info_host, NULL /* allocator */, handle);
        fprintf(stderr, "winemac:VK surface_create STEP6 p_vkCreateMetalSurfaceEXT res=%d handle=%p\n",
                (int)res, (void *)(uintptr_t)*handle);

        macdrv_restore_metal_layer_delegate(metal_layer, saved_delegate);
    }
    else
    {
        VkMacOSSurfaceCreateInfoMVK create_info_host;
        create_info_host.sType = VK_STRUCTURE_TYPE_MACOS_SURFACE_CREATE_INFO_MVK;
        create_info_host.pNext = NULL;
        create_info_host.flags = 0; /* reserved */
        create_info_host.pView = macdrv_view_get_metal_layer(surface->metal_view);

        res = instance->p_vkCreateMacOSSurfaceMVK(instance->host.instance, &create_info_host, NULL /* allocator */, handle);
    }
    if (res != VK_SUCCESS)
    {
        ERR("Failed to create MoltenVK surface, res=%d\n", res);
        goto err;
    }

    /* Strategy E.1-vulkan: kick off a one-shot host-request broadcast right
     * away - UNLESS PROTON_DISABLE_E1_VULKAN_BROADCAST is set, which we use
     * for same-process titles (Elden Ring etc.) where cross-process layer
     * hosting isn't needed and the CAContext.contextWithCGSConnection path
     * has been observed to crash intermittently on macOS 26 with a stale
     * layer retain.
     *
     * macdrv_client_surface_update will continue broadcasting on every
     * covers that race. */
    /* Bug (Proton macOS) 2026-04-29: scope to Steam processes only, same
     * reasoning as PROTON_DISABLE_E1 (env-leak from Steam.exe to every
     * `-applaunch` game would break their Vulkan-side layer broadcast).
     * vulkan.c is unix-side (`#pragma makedep unix`) so Win32 API isn't
     * directly callable; use _NSGetArgv to peek at the argv our wine
     * loader was started with - the PE path appears as one of the
     * arguments. */
    int disable_e1_vk = 0;
    if (getenv("PROTON_DISABLE_E1_VULKAN_BROADCAST"))
    {
        extern char ***_NSGetArgv(void);
        extern int *_NSGetArgc(void);
        char **argv = *_NSGetArgv();
        int argc = *_NSGetArgc(), i;
        for (i = 0; i < argc; i++)
        {
            const char *a = argv[i];
            const char *base = strrchr(a, '/');
            const char *back = strrchr(a, '\\');
            if (back > base) base = back;
            base = base ? base + 1 : a;
            if (!strcasecmp(base, "steam.exe") ||
                !strcasecmp(base, "steamwebhelper.exe") ||
                !strcasecmp(base, "gldriverquery.exe") ||
                !strcasecmp(base, "gldriverquery64.exe"))
            {
                disable_e1_vk = 1;
                break;
            }
        }
    }
    if (!disable_e1_vk)
    {
        void *metal_layer = (void *)macdrv_view_get_metal_layer(surface->metal_view);
        HWND toplevel = NtUserGetAncestor(hwnd, GA_ROOT);
        if (metal_layer)
        {
            fprintf(stderr,
                    "winemac:E.1-vulkan - surface_create kick hwnd=%p toplevel=%p layer=%p\n",
                    hwnd, toplevel, metal_layer);
            macdrv_broadcast_vulkan_layer_host_request((void *)toplevel, metal_layer);
            fprintf(stderr, "winemac:VK surface_create STEP7 broadcast returned\n");
        }
    }
    fprintf(stderr, "winemac:VK surface_create STEP8 about to set client=&surface->client surface=%p client_ptr=%p\n",
            surface, client);

    *client = &surface->client;
    fprintf(stderr, "winemac:VK surface_create STEP9 client set to %p, returning VK_SUCCESS\n", *client);
    TRACE("Created surface=0x%s, client=%p\n", wine_dbgstr_longlong(*handle), *client);
    return VK_SUCCESS;

err:
    client_surface_release(&surface->client);
    return VK_ERROR_INCOMPATIBLE_DRIVER;
}

static VkBool32 macdrv_get_physical_device_presentation_support(struct vulkan_physical_device *physical_device,
        uint32_t index)
{
    TRACE("%p %u\n", physical_device, index);

    return VK_TRUE;
}

static BOOL use_VK_EXT_metal_surface;

static void macdrv_map_instance_extensions(struct vulkan_instance_extensions *extensions)
{
    if (use_VK_EXT_metal_surface)
    {
        if (extensions->has_VK_KHR_win32_surface) extensions->has_VK_EXT_metal_surface = 1;
        if (extensions->has_VK_EXT_metal_surface) extensions->has_VK_KHR_win32_surface = 1;
    }
    else
    {
        if (extensions->has_VK_KHR_win32_surface) extensions->has_VK_MVK_macos_surface = 1;
        if (extensions->has_VK_MVK_macos_surface) extensions->has_VK_KHR_win32_surface = 1;
    }
}

static void macdrv_map_device_extensions(struct vulkan_device_extensions *extensions)
{
}

static const struct vulkan_driver_funcs macdrv_vulkan_driver_funcs =
{
    .p_vulkan_surface_create = macdrv_vulkan_surface_create,
    .p_get_physical_device_presentation_support = macdrv_get_physical_device_presentation_support,
    .p_map_instance_extensions = macdrv_map_instance_extensions,
    .p_map_device_extensions = macdrv_map_device_extensions,
};

UINT macdrv_VulkanInit(UINT version, void *vulkan_handle, const struct vulkan_driver_funcs **driver_funcs)
{
    if (version != WINE_VULKAN_DRIVER_VERSION)
    {
        ERR("version mismatch, win32u wants %u but driver has %u\n", version, WINE_VULKAN_DRIVER_VERSION);
        return STATUS_INVALID_PARAMETER;
    }

    use_VK_EXT_metal_surface = !!dlsym(vulkan_handle, "vkCreateMetalSurfaceEXT");

    *driver_funcs = &macdrv_vulkan_driver_funcs;
    return STATUS_SUCCESS;
}
