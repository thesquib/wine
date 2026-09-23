/*
 * The vcpu_el1 guest page image, for the arm64 macOS vCPU mode.
 *
 * Same instructions as openrosetta's vcpu/vcpu_el1_blob.S (MIT), carried here as a top-level asm block because
 * makedep would assemble a .S unix source for every architecture. proton-darwin mac/vcpu/tests checks that both
 * assemble to the same bytes.
 */

#if 0
#pragma makedep unix
#endif

#if defined(__APPLE__) && defined(__aarch64__)
__asm__( ".section __TEXT,__const\n\t"
         ".p2align 12\n\t"
         ".globl _vel1_blob_start\n\t"
         ".globl _vel1_blob_end\n"
         "_vel1_blob_start:\n\t"
         ".irp slot, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15\n\t"
         ".p2align 7\n\t"
         "hvc #(0x200 + \\slot)\n\t"
         "b .\n\t"
         ".endr\n\t"
         ".p2align 11\n"
         "_vel1_syscall_stub:\n\t"
         "hint #34\n\t"
         "hvc #0x100\n\t"
         "ret\n\t"
         "udf #0\n"
         "_vel1_unixcall_stub:\n\t"
         "hint #34\n\t"
         "hvc #0x101\n\t"
         "ret\n\t"
         "udf #0\n"
         "_vel1_blob_end:\n\t"
         ".text" );
#endif
