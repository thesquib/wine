/*
 * Emulator initialisation code
 *
 * Copyright 2000 Alexandre Julliard
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

#include "config.h"

#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dlfcn.h>
#include <limits.h>
#ifdef HAVE_SYS_SYSCTL_H
# include <sys/sysctl.h>
#endif
#ifdef __APPLE__
# include <mach-o/dyld.h>
# include <mach-o/getsect.h>
#endif

#include "main.h"

#if defined(__APPLE__) && !defined(HAVE_WINE_PRELOADER)

/* Not using the preloader (x86_64, or arm64):
 * Reserve the same areas as the preloader does, but using zero-fill sections
 * (the only way to prevent system frameworks from using them, including allocations
 * before main() runs).
 *
 * On arm64 an 8GB WINE_RESERVE section is not possible: the dyld shared cache
 * loads around 0x18e000000, so there is nowhere near that much room below it.
 * Instead the loader is linked with a large -pagezero_size (see configure.ac),
 * which reserves all the low address space and, as a side effect, keeps our
 * mandatory-PIE __TEXT out of the shared-cache band -- landing in it gets the
 * process SIGKILLed by AppleSystemPolicy before dyld hands control over.
 *
 * PAGEZERO cannot be mapped into as-is, so init_reserved_areas() reads its real
 * size back out of our own Mach-O header and mmaps PROT_NONE over the range,
 * turning it into an ordinary reservation ntdll can carve KUSER_SHARED_DATA and
 * the rest of the Windows address space out of.
 */
#ifdef __x86_64__
__asm__(".zerofill WINE_RESERVE,WINE_RESERVE");
static char __wine_reserve[0x1fffff000] __attribute__((section("WINE_RESERVE, WINE_RESERVE")));
#endif

__asm__(".zerofill WINE_TOP_DOWN,WINE_TOP_DOWN");
/* arm64 needs space above PAGEZERO reserved by dyld before libmalloc initializes.
 * The slid range covers conventional 0x140000000 fixed-base images without replacing host allocations. */
#ifdef __aarch64__
static char __wine_top_down[0x60000000]
#else
static char __wine_top_down[0x001ff0000]
#endif
    __attribute__((section("WINE_TOP_DOWN, WINE_TOP_DOWN")));

/* Not const: on arm64 entry 0's size is only known once we can read our own
 * __PAGEZERO back at runtime. */
static struct wine_preload_info preload_info[] =
{
#ifdef __x86_64__
    { __wine_reserve,  sizeof(__wine_reserve)  }, /*         0x1000 -    0x200000000: low 8GB */
#else
    { (void *)0x10000, 0 },                       /*        0x10000 - end of PAGEZERO, filled in below (16K aligned) */
#endif
    { __wine_top_down, sizeof(__wine_top_down) }, /* 0x7ff000000000 - 0x7ff001ff0000: top-down allocations + virtual heap */
    { 0, 0 }                                      /* end of list */
};

__attribute((visibility("default"))) struct wine_preload_info *wine_main_preload_info = preload_info;

/* PROTON_DARWIN native route: set when PAGEZERO could be replaced by our reservation, which only an executable
 * with the cross-architecture entitlement may do (wine-native.app). ntdll then runs without vCPUs. */
__attribute((visibility("default"))) int wine_main_native_route = 0;

static void init_reserved_areas(void)
{
    int i;

#ifndef __x86_64__
    /* Fill in the size of PAGEZERO. ASLR moves the image, so the link-time
     * -pagezero_size has to be read back from the loaded header rather than
     * hardcoded here. */
    {
        Dl_info dli;

        if (dladdr( (void *)&init_reserved_areas, &dli ))
        {
            unsigned long size = 0;
            getsegmentdata( dli.dli_fbase, "__PAGEZERO", &size );
            if (size) preload_info[0].size = size - (uintptr_t)preload_info[0].addr;
        }
    }
#endif

    for (i = 0; wine_main_preload_info[i].size != 0; i++)
    {
        /* Match how the preloader maps reserved areas: */
        void *ret = mmap(wine_main_preload_info[i].addr, wine_main_preload_info[i].size, PROT_NONE,
                         MAP_FIXED | MAP_NORESERVE | MAP_PRIVATE | MAP_ANON, -1, 0);
#ifndef __x86_64__
        /* fails on the ad-hoc vCPU loader (PAGEZERO is not replaceable), succeeds on the entitled one */
        if (!i) wine_main_native_route = (ret == wine_main_preload_info[i].addr);
#endif
        (void)ret;
    }
}

#else

/* the preloader will set these variables */
__attribute((visibility("default"))) struct r_debug *wine_r_debug = NULL;
__attribute((visibility("default"))) struct wine_preload_info *wine_main_preload_info = NULL;

static void init_reserved_areas(void)
{
}

#endif

/* canonicalize path and return its directory name */
static char *realpath_dirname( const char *name )
{
    char *p, *fullpath = realpath( name, NULL );

    if (fullpath)
    {
        p = strrchr( fullpath, '/' );
        if (p == fullpath) p++;
        if (p) *p = 0;
    }
    return fullpath;
}

/* if string ends with tail, remove it */
static char *remove_tail( const char *str, const char *tail )
{
    size_t len = strlen( str );
    size_t tail_len = strlen( tail );
    char *ret;

    if (len < tail_len) return NULL;
    if (strcmp( str + len - tail_len, tail )) return NULL;
    ret = malloc( len - tail_len + 1 );
    memcpy( ret, str, len - tail_len );
    ret[len - tail_len] = 0;
    return ret;
}

/* build a path from the specified dir and name */
static char *build_path( const char *dir, const char *name )
{
    size_t len = strlen( dir );
    char *ret = malloc( len + strlen( name ) + 2 );

    memcpy( ret, dir, len );
    if (len && ret[len - 1] != '/') ret[len++] = '/';
    strcpy( ret + len, name );
    return ret;
}

static const char *get_self_exe(void)
{
#if defined(__linux__) || defined(__FreeBSD_kernel__) || defined(__NetBSD__)
    return "/proc/self/exe";
#elif defined (__FreeBSD__) || defined(__DragonFly__)
    static int pathname[] = { CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1 };
    size_t path_size = PATH_MAX;
    char *path = malloc( path_size );
    if (path && !sysctl( pathname, sizeof(pathname)/sizeof(pathname[0]), path, &path_size, NULL, 0 ))
        return path;
    free( path );
#elif defined(__APPLE__)
    uint32_t path_size = PATH_MAX;
    char *path = malloc( path_size );
    if (path && !_NSGetExecutablePath( path, &path_size ))
        return path;
    free( path );
#endif
    return NULL;
}

static void *try_dlopen( const char *argv0 )
{
    char *dir, *path, *p;
    void *handle;

    if (!argv0) return NULL;

    if ((p = remove_tail( argv0, "i386-unix/wine64")))
    {
        path = build_path( p, "x86_64-unix/ntdll.so" );
        free( p );
        handle = dlopen( path, RTLD_NOW );
        free( path );
        return handle;
    }

    if (!(dir = realpath_dirname( argv0 ))) return NULL;

    /* <arch>-unix/wine-native.app/Contents/MacOS/wine: ntdll.so is next to the bundle */
    if ((p = remove_tail( dir, ".app/Contents/MacOS" )) && (path = strrchr( p, '/' )))
    {
        *path = 0;
        free( dir );
        dir = p;
        p = NULL;
    }
    else
    {
        free( p );
        p = NULL;
    }

    if ((p = remove_tail( dir, "/loader" )))
        path = build_path( p, "dlls/ntdll/ntdll.so" );
    else
        path = build_path( dir, "ntdll.so" );

    handle = dlopen( path, RTLD_NOW );
    free( p );
    free( dir );
    free( path );
    return handle;
}


/**********************************************************************
 *           main
 */
#if defined(__APPLE__) && defined(__aarch64__) && !defined(HAVE_WINE_PRELOADER)
#include <spawn.h>
#include <crt_externs.h>

/* PROTON_DARWIN native route, opt-in PMW_NATIVE_4K=1: re-exec in place with 4-KB host pages, so Windows 4-KB page
 * protections are exact (a 16-KB host page takes the union of its four pages; FEX's x86 SMC traps and write-watch
 * break on that). Only an executable with the cross-architecture entitlement gets 4 KB; a plain execve drops back
 * to 16 KB, which is why every native process (children included) passes through here. */
static void native_4k_relaunch( char *argv[] )
{
    static const char guard[] = "PMW_NATIVE_4K_RELAUNCHED";
    const char *opt = getenv( "PMW_NATIVE_4K" );
    posix_spawnattr_t attr;
    int err;

    if (!opt || strcmp( opt, "1" )) return;
    if (sysconf( _SC_PAGESIZE ) == 4096)
    {
        unsetenv( guard );  /* children start at 16 KB again and must relaunch themselves */
        return;
    }
    if (getenv( guard ))
    {
        fprintf( stderr, "wine: PMW_NATIVE_4K relaunch did not give 4-KB pages, continuing at %ld\n",
                 sysconf( _SC_PAGESIZE ) );
        unsetenv( guard );
        return;
    }
    setenv( guard, "1", 1 );
    posix_spawnattr_init( &attr );
    posix_spawnattr_setflags( &attr, POSIX_SPAWN_SETEXEC );
    if (!(err = posix_spawnattr_set_4k_page_size_np( &attr )))
        err = posix_spawn( NULL, get_self_exe(), NULL, &attr, argv, *_NSGetEnviron() );
    posix_spawnattr_destroy( &attr );
    fprintf( stderr, "wine: PMW_NATIVE_4K relaunch failed (%d), continuing with 16-KB pages\n", err );
    unsetenv( guard );
}
#endif

int main( int argc, char *argv[] )
{
    void *handle;

    init_reserved_areas();
#if defined(__APPLE__) && defined(__aarch64__) && !defined(HAVE_WINE_PRELOADER)
    if (wine_main_native_route) native_4k_relaunch( argv );
#endif

    if ((handle = try_dlopen( get_self_exe() )) ||
        (handle = try_dlopen( argv[0] )))
    {
        void (*init_func)(int, char **) = dlsym( handle, "__wine_main" );
        if (init_func) init_func( argc, argv );
        fprintf( stderr, "wine: __wine_main function not found in ntdll.so\n" );
        exit(1);
    }

    fprintf( stderr, "wine: could not load ntdll.so: %s\n", dlerror() );
    pthread_detach( pthread_self() );  /* force importing libpthread for OpenGL */
    exit(1);
}
