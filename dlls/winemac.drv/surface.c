/*
 * Mac driver window surface implementation
 *
 * Copyright 1993, 1994, 2011 Alexandre Julliard
 * Copyright 2006 Damjan Jovanovic
 * Copyright 2012, 2013 Ken Thomases for CodeWeavers, Inc.
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

#include <stdio.h>
#include <stdlib.h>

#include "macdrv.h"
#include "winuser.h"

WINE_DEFAULT_DEBUG_CHANNEL(bitblt);

/* PROTON_CEF_FLUSH: log-only window-surface flush probe (Steam-in-bottle CEF
 * black-window investigation, 2026-06-21). Default off. Tag [CEF-FLUSH].
 * Tunable throttle: PROTON_CEF_FLUSH_WARMUP (default 40), PROTON_CEF_FLUSH_PERIOD
 * (default 120). Remove after the surface-vs-present hypothesis is split. */
static int proton_cef_flush_enabled(void)
{
    static int cached = -1;
    if (cached == -1) {
        const char *v = getenv("PROTON_CEF_FLUSH");
        cached = (v && v[0] && !(v[0] == '0' && v[1] == '\0')) ? 1 : 0;
    }
    return cached;
}

static unsigned long proton_cef_flush_warmup(void)
{
    static long cached = -1;
    if (cached < 0) {
        const char *v = getenv("PROTON_CEF_FLUSH_WARMUP");
        cached = (v && v[0]) ? atol(v) : 40;
        if (cached < 0) cached = 0;
    }
    return (unsigned long)cached;
}

static unsigned long proton_cef_flush_period(void)
{
    static long cached = -1;
    if (cached < 0) {
        const char *v = getenv("PROTON_CEF_FLUSH_PERIOD");
        cached = (v && v[0]) ? atol(v) : 120;
        if (cached < 1) cached = 1;
    }
    return (unsigned long)cached;
}

static inline int get_dib_stride(int width, int bpp)
{
    return ((width * bpp + 31) >> 3) & ~3;
}

static inline int get_dib_image_size(const BITMAPINFO *info)
{
    return get_dib_stride(info->bmiHeader.biWidth, info->bmiHeader.biBitCount)
        * abs(info->bmiHeader.biHeight);
}


struct macdrv_window_surface
{
    struct window_surface   header;
    macdrv_window           window;
    CGDataProviderRef       provider;
};

static struct macdrv_window_surface *get_mac_surface(struct window_surface *surface);

static CGDataProviderRef data_provider_create(size_t size, void **bits)
{
    CGDataProviderRef provider;
    CFMutableDataRef data;

    if (!(data = CFDataCreateMutable(kCFAllocatorDefault, size))) return NULL;
    CFDataSetLength(data, size);

    if ((provider = CGDataProviderCreateWithCFData(data)))
        *bits = CFDataGetMutableBytePtr(data);
    CFRelease(data);

    return provider;
}

/***********************************************************************
 *              macdrv_surface_set_clip
 */
static void macdrv_surface_set_clip(struct window_surface *window_surface, const RECT *rects, UINT count)
{
}

/***********************************************************************
 *              macdrv_surface_flush
 */
static BOOL macdrv_surface_flush(struct window_surface *window_surface, const RECT *rect, const RECT *dirty,
                                 const BITMAPINFO *color_info, const void *color_bits, BOOL shape_changed,
                                 const BITMAPINFO *shape_info, const void *shape_bits)
{
    struct macdrv_window_surface *surface = get_mac_surface(window_surface);
    CGImageAlphaInfo alpha_info = (window_surface->alpha_mask ? kCGImageAlphaPremultipliedFirst : kCGImageAlphaNoneSkipFirst);
    CGColorSpaceRef colorspace;
    CGImageRef image;

    if (proton_cef_flush_enabled())
    {
        static unsigned long count = 0;
        unsigned long n = __atomic_add_fetch(&count, 1, __ATOMIC_RELAXED);
        if (n <= proton_cef_flush_warmup() || (n % proton_cef_flush_period()) == 0)
        {
            int w = color_info->bmiHeader.biWidth;
            int h = abs(color_info->bmiHeader.biHeight);
            int stride = h ? (int)(color_info->bmiHeader.biSizeImage / h) : 0;
            const unsigned char *bits = color_bits;
            unsigned int cpx = 0;
            int nonblack = 0, sampled = 0, gx, gy;
            if (bits && w > 0 && h > 0 && stride > 0)
            {
                int cx = w / 2, cy = h / 2;
                cpx = *(const unsigned int *)(bits + (size_t)cy * stride + (size_t)cx * 4);
                for (gy = 0; gy < 16; gy++)
                    for (gx = 0; gx < 16; gx++)
                    {
                        int px = (w * gx) / 16, py = (h * gy) / 16;
                        unsigned int v = *(const unsigned int *)(bits + (size_t)py * stride + (size_t)px * 4);
                        sampled++;
                        if (v & 0x00ffffff) nonblack++;   /* any non-zero RGB, ignore alpha byte */
                    }
            }
            /* Compare the provider buffer (what the CGImage is built from) to
             * color_bits (what wine just painted). If they differ, the image
             * shows the stale black initial fill, not the content. */
            unsigned int provpx = 0xdeadbeef; size_t provlen = 0;
            if (surface && surface->provider && w > 0 && h > 0 && stride > 0)
            {
                CFDataRef pd = CGDataProviderCopyData(surface->provider);
                if (pd)
                {
                    const unsigned char *pb = CFDataGetBytePtr(pd);
                    provlen = CFDataGetLength(pd);
                    size_t off = (size_t)(h/2) * stride + (size_t)(w/2) * 4;
                    if (pb && off + 4 <= provlen)
                        provpx = *(const unsigned int *)(pb + off);
                    CFRelease(pd);
                }
            }
            fprintf(stderr,
                    "winemac: [CEF-FLUSH] hwnd=%p win=%p rect=%ld,%ld-%ld,%ld dim=%dx%d stride=%d "
                    "centerBGRA=%08x providerCenter=%08x provlen=%zu nonblack=%d/%d alpha_mask=%u n=%lu\n",
                    window_surface->hwnd, surface ? surface->window : NULL,
                    (long)rect->left, (long)rect->top, (long)rect->right, (long)rect->bottom,
                    w, h, stride, cpx, provpx, provlen, nonblack, sampled, window_surface->alpha_mask, n);
            fflush(stderr);
        }
    }

    colorspace = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
    image = CGImageCreate(color_info->bmiHeader.biWidth, abs(color_info->bmiHeader.biHeight), 8, 32,
                          color_info->bmiHeader.biSizeImage / abs(color_info->bmiHeader.biHeight), colorspace,
                          alpha_info | kCGBitmapByteOrder32Little, surface->provider, NULL, retina_on, kCGRenderingIntentDefault);
    CGColorSpaceRelease(colorspace);

    macdrv_window_set_color_image(surface->window, image, cgrect_from_rect(*rect), cgrect_from_rect(*dirty));
    CGImageRelease(image);

    if (shape_changed)
    {
        if (!shape_bits)
            macdrv_window_set_shape_image(surface->window, NULL);
        else
        {
            const BYTE *src = shape_bits;
            CGDataProviderRef provider;
            CGImageRef image;
            BYTE *dst;
            UINT i;

            if (!(provider = data_provider_create(shape_info->bmiHeader.biSizeImage, (void **)&dst))) return TRUE;
            for (i = 0; i < shape_info->bmiHeader.biSizeImage; i++) dst[i] = ~src[i]; /* CGImage mask bits are inverted */

            image = CGImageMaskCreate(shape_info->bmiHeader.biWidth, abs(shape_info->bmiHeader.biHeight), 1, 1,
                                      shape_info->bmiHeader.biSizeImage / abs(shape_info->bmiHeader.biHeight),
                                      provider, NULL, retina_on);
            CGDataProviderRelease(provider);

            macdrv_window_set_shape_image(surface->window, image);
            CGImageRelease(image);
        }
    }

    return TRUE;
}

/***********************************************************************
 *              macdrv_surface_destroy
 */
static void macdrv_surface_destroy(struct window_surface *window_surface)
{
    struct macdrv_window_surface *surface = get_mac_surface(window_surface);

    TRACE("freeing %p\n", surface);
    CGDataProviderRelease(surface->provider);
}

static const struct window_surface_funcs macdrv_surface_funcs =
{
    macdrv_surface_set_clip,
    macdrv_surface_flush,
    macdrv_surface_destroy,
};

static struct macdrv_window_surface *get_mac_surface(struct window_surface *surface)
{
    if (!surface || surface->funcs != &macdrv_surface_funcs) return NULL;
    return (struct macdrv_window_surface *)surface;
}

/***********************************************************************
 *              create_surface
 */
static struct window_surface *create_surface(HWND hwnd, macdrv_window window, const RECT *rect)
{
    struct macdrv_window_surface *surface;
    int width = rect->right - rect->left, height = rect->bottom - rect->top;
    DWORD window_background;
    D3DKMT_CREATEDCFROMMEMORY desc = {.Format = D3DDDIFMT_A8R8G8B8};
    char buffer[FIELD_OFFSET(BITMAPINFO, bmiColors[256])];
    BITMAPINFO *info = (BITMAPINFO *)buffer;
    struct window_surface *window_surface;
    CGDataProviderRef provider;
    HBITMAP bitmap = 0;
    UINT status;
    void *bits;

    memset(info, 0, sizeof(*info));
    info->bmiHeader.biSize        = sizeof(info->bmiHeader);
    info->bmiHeader.biWidth       = width;
    info->bmiHeader.biHeight      = -height; /* top-down */
    info->bmiHeader.biPlanes      = 1;
    info->bmiHeader.biBitCount    = 32;
    info->bmiHeader.biSizeImage   = get_dib_image_size(info);
    info->bmiHeader.biCompression = BI_RGB;

    if (!(provider = data_provider_create(info->bmiHeader.biSizeImage, &bits))) return NULL;
    window_background = macdrv_window_background_color();
    memset_pattern4(bits, &window_background, info->bmiHeader.biSizeImage);

    /* wrap the data in a HBITMAP so we can write to the surface pixels directly */
    desc.Width = info->bmiHeader.biWidth;
    desc.Height = abs(info->bmiHeader.biHeight);
    desc.Pitch = info->bmiHeader.biSizeImage / abs(info->bmiHeader.biHeight);
    desc.pMemory = bits;
    desc.hDeviceDc = NtUserGetDCEx(hwnd, 0, DCX_CACHE | DCX_WINDOW);
    if ((status = NtGdiDdDDICreateDCFromMemory(&desc)))
        ERR("Failed to create HBITMAP, status %#x\n", status);
    else
    {
        bitmap = desc.hBitmap;
        NtGdiDeleteObjectApp(desc.hDc);
    }
    if (desc.hDeviceDc) NtUserReleaseDC(hwnd, desc.hDeviceDc);

    if (!(window_surface = window_surface_create(sizeof(*surface), &macdrv_surface_funcs, hwnd, rect, info, bitmap)))
    {
        if (bitmap) NtGdiDeleteObjectApp(bitmap);
        CGDataProviderRelease(provider);
    }
    else
    {
        surface = get_mac_surface(window_surface);
        surface->window = window;
        surface->provider = provider;
    }

    return window_surface;
}


/***********************************************************************
 *              CreateWindowSurface   (MACDRV.@)
 */
BOOL macdrv_CreateWindowSurface(HWND hwnd, BOOL layered, const RECT *surface_rect, struct window_surface **surface)
{
    struct window_surface *previous;
    struct macdrv_win_data *data;

    TRACE("hwnd %p, layered %u, surface_rect %s, surface %p\n", hwnd, layered, wine_dbgstr_rect(surface_rect), surface);

    if ((previous = *surface) && previous->funcs == &macdrv_surface_funcs) return TRUE;
    if (!(data = get_win_data(hwnd))) return TRUE; /* use default surface */
    if (previous) window_surface_release(previous);

    if (layered)
    {
        data->layered = TRUE;
        data->ulw_layered = TRUE;
    }

    *surface = create_surface(hwnd, data->cocoa_window, surface_rect);

    release_win_data(data);
    return TRUE;
}
