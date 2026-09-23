/*
 * openrosetta's vcpu_el1_live.c (MIT, vendored in vcpu/), built for the arm64 macOS vCPU mode only.
 */

#if 0
#pragma makedep unix
#endif

#if defined(__APPLE__) && defined(__aarch64__)
#pragma clang diagnostic ignored "-Wdeclaration-after-statement"  /* the library is C11 */
#include "vcpu/vcpu_el1_live.c"

/* the only file with hv_* calls from the library; pull in the framework from here so no configure change is needed */
__asm__( ".linker_option \"-framework\", \"Hypervisor\"" );
#endif
