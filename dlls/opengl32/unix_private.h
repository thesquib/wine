/*
 *    Copyright (c) 2000 Lionel Ulmer
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
#ifndef __WINE_OPENGL32_UNIX_PRIVATE_H
#define __WINE_OPENGL32_UNIX_PRIVATE_H

#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <pthread.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "wingdi.h"
#include "ntgdi.h"

#include "wine/opengl_driver.h"
#include "unix_thunks.h"

struct registry_entry
{
    const char *name;      /* name of the extension */
    const char *extension; /* name of the GL/WGL extension */
    size_t offset;         /* offset in the opengl_funcs table */
};

extern const struct registry_entry extension_registry[];
extern const int extension_registry_size;

extern struct opengl_funcs null_opengl_funcs;

static inline const struct opengl_funcs *get_dc_funcs( HDC hdc )
{
    DWORD has_opengl;

    if (NtGdiGetDCDword( hdc, NtGdiHasOpenGL, &has_opengl ) && has_opengl)
        return __wine_get_opengl_driver( WINE_OPENGL_DRIVER_VERSION );

    RtlSetLastWin32Error( ERROR_INVALID_HANDLE );
    return &null_opengl_funcs;
}

#ifdef _WIN64

/* PMW_VCPU: 32-bit caller addresses go through wow64_host_ptr (in a vCPU-mode WoW64 process a 32-bit address is at
 * host BASE + p; BASE is 0 elsewhere). PtrToUlong write-backs of host pointers into the 32-bit space stay: BASE is
 * 4 GiB aligned, so the low 32 bits of such a pointer are its guest address. */

/* an array of 32-bit VALUES (GLintptr / GLsizeiptr) at a 32-bit address */
static inline void *copy_wow64_ptr32s( ULONG address, ULONG count )
{
    ULONG *ptrs = wow64_host_ptr( address );
    void **tmp;

    if (!ptrs || !(tmp = calloc( count, sizeof(*tmp) ))) return NULL;
    while (count--) tmp[count] = ULongToPtr(ptrs[count]);
    return tmp;
}

/* PMW_VCPU: a vertex array / indices / indirect / pixel pack-unpack pointer, which GL reads as an offset into the
 * buffer bound at binding when one is bound and as a client address otherwise: widen it only in the second case. Off
 * the vCPU route both are the same value and no GL query is made. */
static inline void *wow64_gl_buffer_ptr( TEB *teb, GLenum binding, ULONG p )
{
    const struct opengl_funcs *funcs = teb->glTable;
    void *host = wow64_host_ptr( p );
    GLint bound = 0;

    if (host == ULongToPtr( p )) return host;
    funcs->p_glGetIntegerv( binding, &bound );
    return bound ? ULongToPtr( p ) : host;
}

/* an array of 32-bit ADDRESSES at a 32-bit address (binding 0: always addresses, else see wow64_gl_buffer_ptr) */
static inline void *copy_wow64_host_ptr32s( TEB *teb, GLenum binding, ULONG address, ULONG count )
{
    ULONG *ptrs = wow64_host_ptr( address );
    GLint bound = 0;
    void **tmp;

    if (!ptrs || !(tmp = calloc( count, sizeof(*tmp) ))) return NULL;
    if (binding && wow64_host_ptr( 0x10000 ) != ULongToPtr( 0x10000 ))
        ((const struct opengl_funcs *)teb->glTable)->p_glGetIntegerv( binding, &bound );
    while (count--) tmp[count] = bound ? ULongToPtr(ptrs[count]) : wow64_host_ptr(ptrs[count]);
    return tmp;
}

static inline TEB *get_teb64( ULONG teb32 )
{
    TEB32 *teb32_ptr = wow64_host_ptr( teb32 );
    return (TEB *)((char *)teb32_ptr + teb32_ptr->WowTebOffset);
}

extern struct buffer *invalidate_buffer_name( TEB *teb, GLuint name );
extern struct buffer *invalidate_buffer_target( TEB *teb, GLenum target );
extern void free_buffer( const struct opengl_funcs *funcs, struct buffer *buffer );
extern NTSTATUS return_wow64_string( const void *str, PTR32 *wow64_str );

#endif

extern pthread_mutex_t wgl_lock;

extern NTSTATUS process_attach( void *args );
extern NTSTATUS thread_attach( void *args );
extern NTSTATUS process_detach( void *args );
extern NTSTATUS get_pixel_formats( void *args );
extern void set_context_attribute( TEB *teb, GLenum name, const void *value, size_t size );
extern void set_current_fbo( TEB *teb, GLenum target, GLuint framebuffer );
extern GLuint get_default_fbo( TEB *teb, GLenum target );
extern void push_default_fbo( TEB *teb );
extern void pop_default_fbo( TEB *teb );
extern void resolve_default_fbo( TEB *teb );
extern BOOL is_wine_reserved_texture( TEB *teb, GLuint tex );

#endif /* __WINE_OPENGL32_UNIX_PRIVATE_H */
