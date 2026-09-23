/*
 * openrosetta's vcpu_el1.c (MIT, vendored in vcpu/), built for the arm64 macOS vCPU mode only.
 */

#if 0
#pragma makedep unix
#endif

#if defined(__APPLE__) && defined(__aarch64__)
#pragma clang diagnostic ignored "-Wdeclaration-after-statement"  /* the library is C11 */
#include "vcpu/vcpu_el1.c"
#endif
