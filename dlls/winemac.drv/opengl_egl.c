/*
 * Mac driver OpenGL through Mesa EGL (Zink on a Vulkan driver), opt-in with PMW_GL_ZINK=1
 *
 * Apple's OpenGL stops at 2.1 legacy / 4.1 core, so applications asking for a 3.x compatibility context get 2.1.
 * With PMW_GL_ZINK=1 (win32u then loads libEGL as if WINE_USE_EGL=1 and selects Zink) its EGL backend drives Mesa on the
 * surfaceless platform and this file supplies the window drawables: each one is an EGL pbuffer the size of the window
 * client area, and SwapBuffers reads it back and copies it into the window through GDI (the window keeps its normal
 * window surface).  A copy per frame; good enough to bring titles up, not the final present path.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#if 0
#pragma makedep unix
#endif

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "macdrv.h"
#include "winuser.h"
#include "wine/opengl_driver.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(wgl);

#ifdef SONAME_LIBEGL

static const struct opengl_funcs *funcs;
static const struct egl_platform *egl;

struct macdrv_egl_drawable
{
    struct opengl_drawable base;
    HWND                   hwnd;
    EGLConfig              config;
    int                    width;
    int                    height;
    void                  *pixels;
    size_t                 pixels_size;
};

static struct macdrv_egl_drawable *impl_from_opengl_drawable(struct opengl_drawable *base)
{
    return CONTAINING_RECORD(base, struct macdrv_egl_drawable, base);
}

static EGLConfig egl_config_for_format(int format)
{
    return egl->configs[(format - 1) % egl->config_count];
}

static void client_rect_size(HWND hwnd, int *width, int *height)
{
    RECT rect;

    NtUserGetClientRect(hwnd, &rect, NtUserGetDpiForWindow(hwnd));
    *width = max(rect.right - rect.left, 1);
    *height = max(rect.bottom - rect.top, 1);
}

static EGLSurface create_pbuffer(EGLConfig config, int width, int height)
{
    const EGLint attribs[] = { EGL_WIDTH, width, EGL_HEIGHT, height, EGL_NONE };
    return funcs->p_eglCreatePbufferSurface(egl->display, config, attribs);
}

/* window client surfaces: only used so win32u tracks the window; presentation happens in swap */
static void egl_client_destroy(struct client_surface *client) {}
static void egl_client_detach(struct client_surface *client) {}
static void egl_client_update(struct client_surface *client) {}
static void egl_client_present(struct client_surface *client, HDC hdc) {}

static const struct client_surface_funcs egl_client_funcs =
{
    .destroy = egl_client_destroy,
    .detach = egl_client_detach,
    .update = egl_client_update,
    .present = egl_client_present,
};

static void macdrv_egl_drawable_destroy(struct opengl_drawable *base)
{
    struct macdrv_egl_drawable *gl = impl_from_opengl_drawable(base);

    TRACE("%s\n", debugstr_opengl_drawable(base));
    if (gl->base.surface) funcs->p_eglDestroySurface(egl->display, gl->base.surface);
    free(gl->pixels);
}

/* recreate the pbuffer when the window client area changed size; called with the drawable's context current */
static void macdrv_egl_drawable_sync_size(struct macdrv_egl_drawable *gl)
{
    EGLSurface old = gl->base.surface, surface;
    EGLContext ctx = funcs->p_eglGetCurrentContext();
    int width, height;

    client_rect_size(gl->hwnd, &width, &height);
    if (width == gl->width && height == gl->height) return;
    if (!(surface = create_pbuffer(gl->config, width, height)))
    {
        ERR("failed to resize pbuffer to %dx%d, error %#x\n", width, height, funcs->p_eglGetError());
        return;
    }
    TRACE("%s resized %dx%d -> %dx%d\n", debugstr_opengl_drawable(&gl->base), gl->width, gl->height, width, height);
    gl->base.surface = surface;
    gl->width = width;
    gl->height = height;
    if (ctx && funcs->p_eglGetCurrentSurface(EGL_DRAW) == old)
        funcs->p_eglMakeCurrent(egl->display, surface, surface, ctx);
    funcs->p_eglDestroySurface(egl->display, old);
}

static void macdrv_egl_drawable_flush(struct opengl_drawable *base, UINT flags)
{
    struct macdrv_egl_drawable *gl = impl_from_opengl_drawable(base);

    TRACE("%s, flags %#x\n", debugstr_opengl_drawable(base), flags);
    if (flags & GL_FLUSH_INTERVAL) funcs->p_eglSwapInterval(egl->display, abs(base->interval));
    if (flags & GL_FLUSH_UPDATED) macdrv_egl_drawable_sync_size(gl);
}

/* read the pbuffer back and copy it into the window */
static BOOL macdrv_egl_drawable_swap(struct opengl_drawable *base)
{
    struct macdrv_egl_drawable *gl = impl_from_opengl_drawable(base);
    GLint read_fbo = 0, pack_buffer = 0, read_buffer = GL_BACK, alignment = 4, row_length = 0;
    size_t size = (size_t)gl->width * gl->height * 4;
    BITMAPINFO bmi = {{0}};
    HWND hwnd = gl->hwnd;
    HDC hdc;

    if (!hwnd || funcs->p_eglGetCurrentSurface(EGL_DRAW) != gl->base.surface) return TRUE;

    if (size > gl->pixels_size)
    {
        void *pixels = realloc(gl->pixels, size);
        if (!pixels) return FALSE;
        gl->pixels = pixels;
        gl->pixels_size = size;
    }

    funcs->p_glGetIntegerv(GL_READ_FRAMEBUFFER_BINDING, &read_fbo);
    funcs->p_glGetIntegerv(GL_PIXEL_PACK_BUFFER_BINDING, &pack_buffer);
    funcs->p_glGetIntegerv(GL_PACK_ALIGNMENT, &alignment);
    funcs->p_glGetIntegerv(GL_PACK_ROW_LENGTH, &row_length);
    funcs->p_glBindFramebuffer(GL_READ_FRAMEBUFFER, 0);
    funcs->p_glGetIntegerv(GL_READ_BUFFER, &read_buffer);
    funcs->p_glBindBuffer(GL_PIXEL_PACK_BUFFER, 0);
    funcs->p_glPixelStorei(GL_PACK_ALIGNMENT, 4);
    funcs->p_glPixelStorei(GL_PACK_ROW_LENGTH, 0);
    funcs->p_glReadBuffer(GL_BACK);
    funcs->p_glReadPixels(0, 0, gl->width, gl->height, GL_BGRA, GL_UNSIGNED_BYTE, gl->pixels);
    funcs->p_glReadBuffer(read_buffer);
    funcs->p_glPixelStorei(GL_PACK_ROW_LENGTH, row_length);
    funcs->p_glPixelStorei(GL_PACK_ALIGNMENT, alignment);
    funcs->p_glBindBuffer(GL_PIXEL_PACK_BUFFER, pack_buffer);
    funcs->p_glBindFramebuffer(GL_READ_FRAMEBUFFER, read_fbo);

    /* GL rows are bottom-up, which is what a positive-height DIB is */
    bmi.bmiHeader.biSize = sizeof(bmi.bmiHeader);
    bmi.bmiHeader.biWidth = gl->width;
    bmi.bmiHeader.biHeight = gl->height;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;

    if ((hdc = NtUserGetDCEx(hwnd, 0, DCX_CACHE | DCX_USESTYLE)))
    {
        INT lines = NtGdiSetDIBitsToDeviceInternal(hdc, 0, 0, gl->width, gl->height, 0, 0, 0, gl->height, gl->pixels,
                                                   &bmi, DIB_RGB_COLORS, size, sizeof(bmi), FALSE, NULL);
        static int trace = -1;
        static unsigned int frame;
        if (trace == -1) { const char *e = getenv("PMW_GL_ZINK_TRACE"); trace = e && atoi(e); }
        if (trace && !(frame++ % 120))
        {
            const unsigned char *p = gl->pixels;
            unsigned long long sum[3] = {0};
            size_t i, n = 0;
            RECT client;
            for (i = 0; i < size; i += 4 * 97, n++) { sum[0] += p[i + 2]; sum[1] += p[i + 1]; sum[2] += p[i]; }
            NtUserGetClientRect(hwnd, &client, NtUserGetDpiForWindow(hwnd));
            fprintf(stderr, "[PMW-GL-ZINK] frame %u hwnd %p pbuffer %dx%d client %dx%d rgb avg %llu %llu %llu lines %d\n",
                    frame, hwnd, gl->width, gl->height, (int)(client.right - client.left),
                    (int)(client.bottom - client.top), sum[0] / n, sum[1] / n, sum[2] / n, lines);
        }
        NtUserReleaseDC(hwnd, hdc);
    }

    {
        /* PMW_GL_ZINK_FPS=1: presented frames per second, every 2 s (this path has no Vulkan present to count) */
        static int fps = -1;
        static unsigned int frames;
        static struct timespec start;
        struct timespec now;
        double secs;

        if (fps == -1) { const char *e = getenv("PMW_GL_ZINK_FPS"); fps = e && atoi(e); }
        if (fps)
        {
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (!start.tv_sec) start = now;
            frames++;
            secs = (now.tv_sec - start.tv_sec) + (now.tv_nsec - start.tv_nsec) / 1e9;
            if (secs >= 2.0)
            {
                fprintf(stderr, "[PMW-GL-ZINK-FPS] %.1f fps (%.2f ms) %dx%d\n", frames / secs, secs * 1000.0 / frames,
                        gl->width, gl->height);
                frames = 0;
                start = now;
            }
        }
    }
    return TRUE;
}

static const struct opengl_drawable_funcs macdrv_egl_drawable_funcs =
{
    .destroy = macdrv_egl_drawable_destroy,
    .flush = macdrv_egl_drawable_flush,
    .swap = macdrv_egl_drawable_swap,
};

static BOOL macdrv_egl_surface_create(HWND hwnd, BOOL raw, int format, struct opengl_drawable **drawable)
{
    struct opengl_drawable *previous;
    struct macdrv_egl_drawable *gl;
    struct client_surface *client;

    TRACE("hwnd %p, raw %u, format %d\n", hwnd, raw, format);

    if ((previous = *drawable) && previous->format == format) return TRUE;

    if (!(client = client_surface_create(sizeof(*client), &egl_client_funcs, hwnd))) return FALSE;
    gl = opengl_drawable_create(sizeof(*gl), &macdrv_egl_drawable_funcs, format, client);
    client_surface_release(client);
    if (!gl) return FALSE;

    /* a pbuffer only has a back buffer: front buffer rendering goes there too */
    gl->base.buffer_map[0] = GL_BACK_LEFT;
    gl->base.buffer_map[1] = GL_BACK_RIGHT;
    gl->base.buffer_map[GL_FRONT - GL_FRONT_LEFT] = GL_BACK;
    gl->base.buffer_map[GL_FRONT_AND_BACK - GL_FRONT_LEFT] = GL_BACK;

    gl->hwnd = hwnd;
    gl->config = egl_config_for_format(format);
    client_rect_size(hwnd, &gl->width, &gl->height);
    if (!(gl->base.surface = create_pbuffer(gl->config, gl->width, gl->height)))
    {
        ERR("failed to create a %dx%d pbuffer, error %#x\n", gl->width, gl->height, funcs->p_eglGetError());
        opengl_drawable_release(&gl->base);
        return FALSE;
    }

    TRACE("created %s %dx%d with egl_surface %p\n", debugstr_opengl_drawable(&gl->base), gl->width, gl->height,
          gl->base.surface);
    if (previous) opengl_drawable_release(previous);
    *drawable = &gl->base;
    return TRUE;
}

static void macdrv_egl_init_egl_platform(struct egl_platform *platform)
{
    platform->type = EGL_PLATFORM_SURFACELESS_MESA;
    platform->native_display = 0;
    egl = platform;
}

static struct opengl_driver_funcs macdrv_egl_driver_funcs =
{
    .p_init_egl_platform = macdrv_egl_init_egl_platform,
    .p_surface_create = macdrv_egl_surface_create,
};

/* called from macdrv_OpenGLInit when PMW_GL_ZINK=1; win32u has already set up EGL if WINE_USE_EGL=1 */
UINT macdrv_egl_OpenGLInit(const struct opengl_funcs *opengl_funcs, const struct opengl_driver_funcs **driver_funcs)
{
    if (!opengl_funcs->egl_handle)
    {
        ERR("PMW_GL_ZINK=1 but win32u has no EGL (libEGL not found, or WINE_USE_EGL unset)\n");
        return STATUS_NOT_SUPPORTED;
    }
    funcs = opengl_funcs;

    /* win32u's surfaceless EGL driver handles formats, contexts and pbuffers */
    macdrv_egl_driver_funcs.p_get_proc_address = (*driver_funcs)->p_get_proc_address;
    macdrv_egl_driver_funcs.p_init_pixel_formats = (*driver_funcs)->p_init_pixel_formats;
    macdrv_egl_driver_funcs.p_describe_pixel_format = (*driver_funcs)->p_describe_pixel_format;
    macdrv_egl_driver_funcs.p_init_wgl_extensions = (*driver_funcs)->p_init_wgl_extensions;
    macdrv_egl_driver_funcs.p_context_create = (*driver_funcs)->p_context_create;
    macdrv_egl_driver_funcs.p_context_destroy = (*driver_funcs)->p_context_destroy;
    macdrv_egl_driver_funcs.p_make_current = (*driver_funcs)->p_make_current;
    macdrv_egl_driver_funcs.p_pbuffer_create = (*driver_funcs)->p_pbuffer_create;
    macdrv_egl_driver_funcs.p_pbuffer_updated = (*driver_funcs)->p_pbuffer_updated;
    macdrv_egl_driver_funcs.p_pbuffer_bind = (*driver_funcs)->p_pbuffer_bind;

    *driver_funcs = &macdrv_egl_driver_funcs;
    TRACE("using Mesa EGL (Zink) instead of Apple OpenGL\n");
    return STATUS_SUCCESS;
}

#else /* SONAME_LIBEGL */

UINT macdrv_egl_OpenGLInit(const struct opengl_funcs *opengl_funcs, const struct opengl_driver_funcs **driver_funcs)
{
    ERR("PMW_GL_ZINK=1 but this winemac was built without EGL\n");
    return STATUS_NOT_SUPPORTED;
}

#endif /* SONAME_LIBEGL */
