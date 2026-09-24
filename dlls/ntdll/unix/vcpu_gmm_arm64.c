/*
 * openrosetta's gmm.c (MIT, vendored in vcpu/), built for the arm64 macOS vCPU mode only.
 */

#if 0
#pragma makedep unix
#endif

#if defined(__APPLE__) && defined(__aarch64__)
#pragma clang diagnostic ignored "-Wdeclaration-after-statement"  /* the library is C11 */
/* gmm's per-phase wall time of its thin mutator (TEST SUPPORT in gmm.h), reported by PMW_VCPU_PROF: one clock read
 * per phase boundary under gmm's mutex, ~0.3 us against the ~240 us a stage-1 sync costs in Slay the Spire 2's load */
#define GMM_PROFILE 1
#include "vcpu/gmm.c"
#endif
