/*
 * Copyright 2020 Nikolay Sivov for CodeWeavers
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

/*
 * Minimal "present-path" DirectComposition implementation for the macOS / KK
 * stack.  This is NOT the full animation/effect API: it implements just enough
 * of IDCompositionDevice / IDCompositionTarget / IDCompositionVisual that a
 * D3D12 game using a *composition* swap chain (created via
 * IDXGIFactory2::CreateSwapChainForComposition, e.g. Godot 4's d3d12 backend)
 * can bind that swap chain to its HWND and present on screen.
 *
 * The bridge: a composition swap chain is created with no HWND, so DXVK/vkd3d
 * present it to a hidden dummy window.  When the app builds the visual tree
 *   target = CreateTargetForHwnd(hwnd); visual = CreateVisual();
 *   visual->SetContent(swapchain); target->SetRoot(visual); device->Commit();
 * our Commit() walks target -> root visual -> content swap chain, queries the
 * swap chain for the private IDXGIVkCompositionSwapChain interface and hands it
 * the real HWND.  The swap chain then recreates its Vulkan surface against that
 * window, reusing the existing presenter.  If the swap chain does not implement
 * the private interface (older DXVK), Commit() is a successful no-op.
 */

#include <stdarg.h>
#include <stdlib.h>

#define COBJMACROS
#include "windef.h"
#include "winbase.h"
#include "objidl.h"
#include "dxgi.h"
#include "dcomp.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(dcomp);

/* Interface IIDs defined locally to avoid depending on a uuid import lib. */
static const GUID guid_IUnknown =
    {0x00000000,0x0000,0x0000,{0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}};
static const GUID guid_IDCompositionDevice =
    {0xc37ea93a,0xe7aa,0x450d,{0xb1,0x6f,0x97,0x46,0xcb,0x04,0x07,0xf3}};
static const GUID guid_IDCompositionTarget =
    {0xeacdd04c,0x117e,0x4e17,{0x88,0xf4,0xd1,0xb1,0x2b,0x0e,0x3d,0x89}};
static const GUID guid_IDCompositionVisual =
    {0x4d93059d,0x097b,0x4651,{0x9a,0x60,0xf0,0xf2,0x51,0x16,0xe2,0xf3}};

/*
 * Private interface, implemented by our forked DXVK/vkd3d-proton composition
 * swap chain, used to retarget a (hidden) composition swap chain to a real
 * window.  Kept in sync with the same GUID in dxvk and vkd3d-proton.
 */
static const GUID guid_IDXGIVkCompositionSwapChain =
    {0x6a9f1c2e,0x3b4d,0x4e5f,{0x8a,0x1b,0x2c,0x3d,0x4e,0x5f,0x60,0x71}};

typedef struct IDXGIVkCompositionSwapChain IDXGIVkCompositionSwapChain;
typedef struct IDXGIVkCompositionSwapChainVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IDXGIVkCompositionSwapChain *, REFIID, void **);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IDXGIVkCompositionSwapChain *);
    ULONG   (STDMETHODCALLTYPE *Release)(IDXGIVkCompositionSwapChain *);
    HRESULT (STDMETHODCALLTYPE *SetPresentationWindow)(IDXGIVkCompositionSwapChain *, HWND);
} IDXGIVkCompositionSwapChainVtbl;
struct IDXGIVkCompositionSwapChain { const IDXGIVkCompositionSwapChainVtbl *lpVtbl; };

struct dcomp_device;
struct dcomp_target;

struct dcomp_visual
{
    IDCompositionVisual IDCompositionVisual_iface;
    LONG refcount;
    IUnknown *content;          /* the swap chain set via SetContent */
};

struct dcomp_target
{
    IDCompositionTarget IDCompositionTarget_iface;
    LONG refcount;
    HWND hwnd;
    struct dcomp_visual *root;  /* set via SetRoot */
};

struct dcomp_device
{
    IDCompositionDevice IDCompositionDevice_iface;
    LONG refcount;
    struct dcomp_target *target; /* last target created (apps use one per window) */
};

static struct dcomp_visual *impl_from_IDCompositionVisual(IDCompositionVisual *iface)
{
    return CONTAINING_RECORD(iface, struct dcomp_visual, IDCompositionVisual_iface);
}

static struct dcomp_target *impl_from_IDCompositionTarget(IDCompositionTarget *iface)
{
    return CONTAINING_RECORD(iface, struct dcomp_target, IDCompositionTarget_iface);
}

static struct dcomp_device *impl_from_IDCompositionDevice(IDCompositionDevice *iface)
{
    return CONTAINING_RECORD(iface, struct dcomp_device, IDCompositionDevice_iface);
}

/* --------------------------------------------------------------------- */
/* IDCompositionVisual                                                    */
/* --------------------------------------------------------------------- */

static HRESULT STDMETHODCALLTYPE dcomp_visual_QueryInterface(IDCompositionVisual *iface, REFIID iid, void **out)
{
    struct dcomp_visual *visual = impl_from_IDCompositionVisual(iface);

    TRACE("%p, %s, %p.\n", iface, debugstr_guid(iid), out);

    if (IsEqualGUID(iid, &guid_IUnknown) || IsEqualGUID(iid, &guid_IDCompositionVisual))
    {
        IDCompositionVisual_AddRef(&visual->IDCompositionVisual_iface);
        *out = &visual->IDCompositionVisual_iface;
        return S_OK;
    }

    WARN("%s not implemented.\n", debugstr_guid(iid));
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE dcomp_visual_AddRef(IDCompositionVisual *iface)
{
    struct dcomp_visual *visual = impl_from_IDCompositionVisual(iface);
    ULONG refcount = InterlockedIncrement(&visual->refcount);
    TRACE("%p increasing refcount to %lu.\n", iface, refcount);
    return refcount;
}

static ULONG STDMETHODCALLTYPE dcomp_visual_Release(IDCompositionVisual *iface)
{
    struct dcomp_visual *visual = impl_from_IDCompositionVisual(iface);
    ULONG refcount = InterlockedDecrement(&visual->refcount);

    TRACE("%p decreasing refcount to %lu.\n", iface, refcount);

    if (!refcount)
    {
        if (visual->content)
            IUnknown_Release(visual->content);
        free(visual);
    }
    return refcount;
}

static HRESULT STDMETHODCALLTYPE dcomp_visual_SetOffsetXAnimation(IDCompositionVisual *iface, IDCompositionAnimation *animation)
{
    FIXME("%p, %p stub.\n", iface, animation);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dcomp_visual_SetOffsetX(IDCompositionVisual *iface, float offset_x)
{
    TRACE("%p, %.8e.\n", iface, offset_x);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dcomp_visual_SetOffsetYAnimation(IDCompositionVisual *iface, IDCompositionAnimation *animation)
{
    FIXME("%p, %p stub.\n", iface, animation);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dcomp_visual_SetOffsetY(IDCompositionVisual *iface, float offset_y)
{
    TRACE("%p, %.8e.\n", iface, offset_y);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dcomp_visual_SetTransformObject(IDCompositionVisual *iface, IDCompositionTransform *transform)
{
    FIXME("%p, %p stub.\n", iface, transform);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dcomp_visual_SetTransform(IDCompositionVisual *iface, const D2D_MATRIX_3X2_F *matrix)
{
    FIXME("%p, %p stub.\n", iface, matrix);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dcomp_visual_SetTransformParent(IDCompositionVisual *iface, IDCompositionVisual *visual)
{
    FIXME("%p, %p stub.\n", iface, visual);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dcomp_visual_SetEffect(IDCompositionVisual *iface, IDCompositionEffect *effect)
{
    FIXME("%p, %p stub.\n", iface, effect);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dcomp_visual_SetBitmapInterpolationMode(IDCompositionVisual *iface,
        enum DCOMPOSITION_BITMAP_INTERPOLATION_MODE mode)
{
    FIXME("%p, %d stub.\n", iface, mode);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dcomp_visual_SetBorderMode(IDCompositionVisual *iface, enum DCOMPOSITION_BORDER_MODE mode)
{
    FIXME("%p, %d stub.\n", iface, mode);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dcomp_visual_SetClipObject(IDCompositionVisual *iface, IDCompositionClip *clip)
{
    FIXME("%p, %p stub.\n", iface, clip);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dcomp_visual_SetClip(IDCompositionVisual *iface, const D2D_RECT_F *rect)
{
    FIXME("%p, %p stub.\n", iface, rect);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dcomp_visual_SetContent(IDCompositionVisual *iface, IUnknown *content)
{
    struct dcomp_visual *visual = impl_from_IDCompositionVisual(iface);

    TRACE("%p, %p.\n", iface, content);

    if (content)
        IUnknown_AddRef(content);
    if (visual->content)
        IUnknown_Release(visual->content);
    visual->content = content;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dcomp_visual_AddVisual(IDCompositionVisual *iface, IDCompositionVisual *visual,
        BOOL insert_above, IDCompositionVisual *reference_visual)
{
    FIXME("%p, %p, %d, %p stub.\n", iface, visual, insert_above, reference_visual);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dcomp_visual_RemoveVisual(IDCompositionVisual *iface, IDCompositionVisual *visual)
{
    FIXME("%p, %p stub.\n", iface, visual);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dcomp_visual_RemoveAllVisuals(IDCompositionVisual *iface)
{
    FIXME("%p stub.\n", iface);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dcomp_visual_SetCompositeMode(IDCompositionVisual *iface,
        enum DCOMPOSITION_COMPOSITE_MODE mode)
{
    FIXME("%p, %d stub.\n", iface, mode);
    return S_OK;
}

static const struct IDCompositionVisualVtbl dcomp_visual_vtbl =
{
    dcomp_visual_QueryInterface,
    dcomp_visual_AddRef,
    dcomp_visual_Release,
    dcomp_visual_SetOffsetXAnimation,
    dcomp_visual_SetOffsetX,
    dcomp_visual_SetOffsetYAnimation,
    dcomp_visual_SetOffsetY,
    dcomp_visual_SetTransformObject,
    dcomp_visual_SetTransform,
    dcomp_visual_SetTransformParent,
    dcomp_visual_SetEffect,
    dcomp_visual_SetBitmapInterpolationMode,
    dcomp_visual_SetBorderMode,
    dcomp_visual_SetClipObject,
    dcomp_visual_SetClip,
    dcomp_visual_SetContent,
    dcomp_visual_AddVisual,
    dcomp_visual_RemoveVisual,
    dcomp_visual_RemoveAllVisuals,
    dcomp_visual_SetCompositeMode,
};

static HRESULT dcomp_visual_create(struct dcomp_visual **out)
{
    struct dcomp_visual *visual;

    if (!(visual = calloc(1, sizeof(*visual))))
        return E_OUTOFMEMORY;

    visual->IDCompositionVisual_iface.lpVtbl = &dcomp_visual_vtbl;
    visual->refcount = 1;
    *out = visual;
    return S_OK;
}

/* --------------------------------------------------------------------- */
/* IDCompositionTarget                                                    */
/* --------------------------------------------------------------------- */

static HRESULT STDMETHODCALLTYPE dcomp_target_QueryInterface(IDCompositionTarget *iface, REFIID iid, void **out)
{
    struct dcomp_target *target = impl_from_IDCompositionTarget(iface);

    TRACE("%p, %s, %p.\n", iface, debugstr_guid(iid), out);

    if (IsEqualGUID(iid, &guid_IUnknown) || IsEqualGUID(iid, &guid_IDCompositionTarget))
    {
        IDCompositionTarget_AddRef(&target->IDCompositionTarget_iface);
        *out = &target->IDCompositionTarget_iface;
        return S_OK;
    }

    WARN("%s not implemented.\n", debugstr_guid(iid));
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE dcomp_target_AddRef(IDCompositionTarget *iface)
{
    struct dcomp_target *target = impl_from_IDCompositionTarget(iface);
    ULONG refcount = InterlockedIncrement(&target->refcount);
    TRACE("%p increasing refcount to %lu.\n", iface, refcount);
    return refcount;
}

static ULONG STDMETHODCALLTYPE dcomp_target_Release(IDCompositionTarget *iface)
{
    struct dcomp_target *target = impl_from_IDCompositionTarget(iface);
    ULONG refcount = InterlockedDecrement(&target->refcount);

    TRACE("%p decreasing refcount to %lu.\n", iface, refcount);

    if (!refcount)
    {
        if (target->root)
            IDCompositionVisual_Release(&target->root->IDCompositionVisual_iface);
        free(target);
    }
    return refcount;
}

static HRESULT STDMETHODCALLTYPE dcomp_target_SetRoot(IDCompositionTarget *iface, IDCompositionVisual *visual)
{
    struct dcomp_target *target = impl_from_IDCompositionTarget(iface);

    TRACE("%p, %p.\n", iface, visual);

    if (visual)
        IDCompositionVisual_AddRef(visual);
    if (target->root)
        IDCompositionVisual_Release(&target->root->IDCompositionVisual_iface);
    target->root = visual ? impl_from_IDCompositionVisual(visual) : NULL;
    return S_OK;
}

static const struct IDCompositionTargetVtbl dcomp_target_vtbl =
{
    dcomp_target_QueryInterface,
    dcomp_target_AddRef,
    dcomp_target_Release,
    dcomp_target_SetRoot,
};

/* --------------------------------------------------------------------- */
/* IDCompositionDevice                                                    */
/* --------------------------------------------------------------------- */

static HRESULT STDMETHODCALLTYPE dcomp_device_QueryInterface(IDCompositionDevice *iface, REFIID iid, void **out)
{
    struct dcomp_device *device = impl_from_IDCompositionDevice(iface);

    TRACE("%p, %s, %p.\n", iface, debugstr_guid(iid), out);

    if (IsEqualGUID(iid, &guid_IUnknown) || IsEqualGUID(iid, &guid_IDCompositionDevice))
    {
        IDCompositionDevice_AddRef(&device->IDCompositionDevice_iface);
        *out = &device->IDCompositionDevice_iface;
        return S_OK;
    }

    WARN("%s not implemented.\n", debugstr_guid(iid));
    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE dcomp_device_AddRef(IDCompositionDevice *iface)
{
    struct dcomp_device *device = impl_from_IDCompositionDevice(iface);
    ULONG refcount = InterlockedIncrement(&device->refcount);
    TRACE("%p increasing refcount to %lu.\n", iface, refcount);
    return refcount;
}

static ULONG STDMETHODCALLTYPE dcomp_device_Release(IDCompositionDevice *iface)
{
    struct dcomp_device *device = impl_from_IDCompositionDevice(iface);
    ULONG refcount = InterlockedDecrement(&device->refcount);

    TRACE("%p decreasing refcount to %lu.\n", iface, refcount);

    if (!refcount)
    {
        if (device->target)
            IDCompositionTarget_Release(&device->target->IDCompositionTarget_iface);
        free(device);
    }
    return refcount;
}

static HRESULT STDMETHODCALLTYPE dcomp_device_Commit(IDCompositionDevice *iface)
{
    struct dcomp_device *device = impl_from_IDCompositionDevice(iface);
    IDXGIVkCompositionSwapChain *bridge;
    struct dcomp_target *target;
    IUnknown *content;
    HRESULT hr;

    TRACE("%p.\n", iface);

    /* Bind the root visual's content swap chain to the target's window so it
     * presents on screen.  Walk device -> target -> root visual -> content. */
    if (!(target = device->target) || !target->root || !(content = target->root->content))
        return S_OK;

    if (SUCCEEDED(hr = IUnknown_QueryInterface(content, &guid_IDXGIVkCompositionSwapChain, (void **)&bridge)))
    {
        TRACE("Retargeting composition swap chain %p to hwnd %p.\n", content, target->hwnd);
        hr = bridge->lpVtbl->SetPresentationWindow(bridge, target->hwnd);
        bridge->lpVtbl->Release(bridge);
        if (FAILED(hr))
            WARN("SetPresentationWindow failed, hr %#lx.\n", hr);
    }
    else
    {
        /* Older swap chain without the private interface: nothing to do here;
         * presentation falls back to whatever window the swap chain owns. */
        TRACE("Content %p does not implement IDXGIVkCompositionSwapChain.\n", content);
    }

    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dcomp_device_WaitForCommitCompletion(IDCompositionDevice *iface)
{
    TRACE("%p.\n", iface);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dcomp_device_GetFrameStatistics(IDCompositionDevice *iface,
        DCOMPOSITION_FRAME_STATISTICS *statistics)
{
    FIXME("%p, %p stub.\n", iface, statistics);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dcomp_device_CreateTargetForHwnd(IDCompositionDevice *iface, HWND hwnd,
        BOOL topmost, IDCompositionTarget **out)
{
    struct dcomp_device *device = impl_from_IDCompositionDevice(iface);
    struct dcomp_target *target;

    TRACE("%p, %p, %d, %p.\n", iface, hwnd, topmost, out);

    if (!out)
        return E_INVALIDARG;
    *out = NULL;

    if (!(target = calloc(1, sizeof(*target))))
        return E_OUTOFMEMORY;

    target->IDCompositionTarget_iface.lpVtbl = &dcomp_target_vtbl;
    target->refcount = 1;
    target->hwnd = hwnd;

    /* Remember the target so Commit() can find (hwnd, swap chain). Apps create
     * one target per device/window. */
    if (device->target)
        IDCompositionTarget_Release(&device->target->IDCompositionTarget_iface);
    IDCompositionTarget_AddRef(&target->IDCompositionTarget_iface);
    device->target = target;

    *out = &target->IDCompositionTarget_iface;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dcomp_device_CreateVisual(IDCompositionDevice *iface, IDCompositionVisual **out)
{
    struct dcomp_visual *visual;
    HRESULT hr;

    TRACE("%p, %p.\n", iface, out);

    if (!out)
        return E_INVALIDARG;
    *out = NULL;

    if (FAILED(hr = dcomp_visual_create(&visual)))
        return hr;

    *out = &visual->IDCompositionVisual_iface;
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE dcomp_device_CreateSurface(IDCompositionDevice *iface, UINT width, UINT height,
        DXGI_FORMAT pixel_format, DXGI_ALPHA_MODE alpha_mode, IDCompositionSurface **surface)
{
    FIXME("%p, %u, %u, %d, %d, %p stub.\n", iface, width, height, pixel_format, alpha_mode, surface);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dcomp_device_CreateVirtualSurface(IDCompositionDevice *iface, UINT width, UINT height,
        DXGI_FORMAT pixel_format, DXGI_ALPHA_MODE alpha_mode, IDCompositionVirtualSurface **surface)
{
    FIXME("%p, %u, %u, %d, %d, %p stub.\n", iface, width, height, pixel_format, alpha_mode, surface);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dcomp_device_CreateSurfaceFromHandle(IDCompositionDevice *iface, HANDLE handle,
        IUnknown **surface)
{
    FIXME("%p, %p, %p stub.\n", iface, handle, surface);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dcomp_device_CreateSurfaceFromHwnd(IDCompositionDevice *iface, HWND hwnd,
        IUnknown **surface)
{
    FIXME("%p, %p, %p stub.\n", iface, hwnd, surface);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dcomp_device_CreateTranslateTransform(IDCompositionDevice *iface,
        IDCompositionTranslateTransform **transform)
{
    FIXME("%p, %p stub.\n", iface, transform);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dcomp_device_CreateScaleTransform(IDCompositionDevice *iface,
        IDCompositionScaleTransform **transform)
{
    FIXME("%p, %p stub.\n", iface, transform);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dcomp_device_CreateRotateTransform(IDCompositionDevice *iface,
        IDCompositionRotateTransform **transform)
{
    FIXME("%p, %p stub.\n", iface, transform);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dcomp_device_CreateSkewTransform(IDCompositionDevice *iface,
        IDCompositionSkewTransform **transform)
{
    FIXME("%p, %p stub.\n", iface, transform);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dcomp_device_CreateMatrixTransform(IDCompositionDevice *iface,
        IDCompositionMatrixTransform **transform)
{
    FIXME("%p, %p stub.\n", iface, transform);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dcomp_device_CreateTransformGroup(IDCompositionDevice *iface,
        IDCompositionTransform **transforms, UINT elements, IDCompositionTransform **transform_group)
{
    FIXME("%p, %p, %u, %p stub.\n", iface, transforms, elements, transform_group);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dcomp_device_CreateTranslateTransform3D(IDCompositionDevice *iface,
        IDCompositionTranslateTransform3D **transform_3d)
{
    FIXME("%p, %p stub.\n", iface, transform_3d);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dcomp_device_CreateScaleTransform3D(IDCompositionDevice *iface,
        IDCompositionScaleTransform3D **transform_3d)
{
    FIXME("%p, %p stub.\n", iface, transform_3d);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dcomp_device_CreateRotateTransform3D(IDCompositionDevice *iface,
        IDCompositionRotateTransform3D **transform_3d)
{
    FIXME("%p, %p stub.\n", iface, transform_3d);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dcomp_device_CreateMatrixTransform3D(IDCompositionDevice *iface,
        IDCompositionMatrixTransform3D **transform_3d)
{
    FIXME("%p, %p stub.\n", iface, transform_3d);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dcomp_device_CreateTransform3DGroup(IDCompositionDevice *iface,
        IDCompositionTransform3D **transforms_3d, UINT elements, IDCompositionTransform3D **transform_3d_group)
{
    FIXME("%p, %p, %u, %p stub.\n", iface, transforms_3d, elements, transform_3d_group);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dcomp_device_CreateEffectGroup(IDCompositionDevice *iface,
        IDCompositionEffectGroup **effect_group)
{
    FIXME("%p, %p stub.\n", iface, effect_group);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dcomp_device_CreateRectangleClip(IDCompositionDevice *iface,
        IDCompositionRectangleClip **clip)
{
    FIXME("%p, %p stub.\n", iface, clip);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dcomp_device_CreateAnimation(IDCompositionDevice *iface,
        IDCompositionAnimation **animation)
{
    FIXME("%p, %p stub.\n", iface, animation);
    return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE dcomp_device_CheckDeviceState(IDCompositionDevice *iface, BOOL *valid)
{
    TRACE("%p, %p.\n", iface, valid);
    if (valid)
        *valid = TRUE;
    return S_OK;
}

static const struct IDCompositionDeviceVtbl dcomp_device_vtbl =
{
    dcomp_device_QueryInterface,
    dcomp_device_AddRef,
    dcomp_device_Release,
    dcomp_device_Commit,
    dcomp_device_WaitForCommitCompletion,
    dcomp_device_GetFrameStatistics,
    dcomp_device_CreateTargetForHwnd,
    dcomp_device_CreateVisual,
    dcomp_device_CreateSurface,
    dcomp_device_CreateVirtualSurface,
    dcomp_device_CreateSurfaceFromHandle,
    dcomp_device_CreateSurfaceFromHwnd,
    dcomp_device_CreateTranslateTransform,
    dcomp_device_CreateScaleTransform,
    dcomp_device_CreateRotateTransform,
    dcomp_device_CreateSkewTransform,
    dcomp_device_CreateMatrixTransform,
    dcomp_device_CreateTransformGroup,
    dcomp_device_CreateTranslateTransform3D,
    dcomp_device_CreateScaleTransform3D,
    dcomp_device_CreateRotateTransform3D,
    dcomp_device_CreateMatrixTransform3D,
    dcomp_device_CreateTransform3DGroup,
    dcomp_device_CreateEffectGroup,
    dcomp_device_CreateRectangleClip,
    dcomp_device_CreateAnimation,
    dcomp_device_CheckDeviceState,
};

static HRESULT dcomp_device_create(REFIID iid, void **out)
{
    struct dcomp_device *device;
    HRESULT hr;

    if (!(device = calloc(1, sizeof(*device))))
        return E_OUTOFMEMORY;

    device->IDCompositionDevice_iface.lpVtbl = &dcomp_device_vtbl;
    device->refcount = 1;

    hr = IDCompositionDevice_QueryInterface(&device->IDCompositionDevice_iface, iid, out);
    IDCompositionDevice_Release(&device->IDCompositionDevice_iface);
    return hr;
}

/* --------------------------------------------------------------------- */
/* Entry points                                                          */
/* --------------------------------------------------------------------- */

HRESULT WINAPI DCompositionCreateDevice(IDXGIDevice *dxgi_device, REFIID iid, void **device)
{
    TRACE("%p, %s, %p.\n", dxgi_device, debugstr_guid(iid), device);

    if (!device)
        return E_INVALIDARG;

    return dcomp_device_create(iid, device);
}

HRESULT WINAPI DCompositionCreateDevice2(IUnknown *rendering_device, REFIID iid, void **device)
{
    TRACE("%p, %s, %p.\n", rendering_device, debugstr_guid(iid), device);

    if (!device)
        return E_INVALIDARG;

    return dcomp_device_create(iid, device);
}

HRESULT WINAPI DCompositionCreateDevice3(IUnknown *rendering_device, REFIID iid, void **device)
{
    TRACE("%p, %s, %p.\n", rendering_device, debugstr_guid(iid), device);

    if (!device)
        return E_INVALIDARG;

    return dcomp_device_create(iid, device);
}
