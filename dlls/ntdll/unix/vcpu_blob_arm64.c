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
         "_vel1_tlbi_stub:\n\t"
         ".irp k, 8,7,6,5,4,3,2,1\n\t"
         "dsb ish\n\t"
         "b Lvel1_tlbi_t\\k\n\t"
         ".endr\n"
         "Lvel1_tlbi_t8:\n\t"
         "tlbi vale1is, x7\n"
         "Lvel1_tlbi_t7:\n\t"
         "tlbi vale1is, x6\n"
         "Lvel1_tlbi_t6:\n\t"
         "tlbi vale1is, x5\n"
         "Lvel1_tlbi_t5:\n\t"
         "tlbi vale1is, x4\n"
         "Lvel1_tlbi_t4:\n\t"
         "tlbi vale1is, x3\n"
         "Lvel1_tlbi_t3:\n\t"
         "tlbi vale1is, x2\n"
         "Lvel1_tlbi_t2:\n\t"
         "tlbi vale1is, x1\n"
         "Lvel1_tlbi_t1:\n\t"
         "tlbi vale1is, x0\n\t"
         "dsb ish\n\t"
         "isb\n"
         "_vel1_tlbi_hvc:\n\t"
         "hvc #0x102\n\t"
         "b .\n"
         "_vel1_tlbi_all:\n\t"
         "dsb ish\n\t"
         "tlbi vmalle1is\n\t"
         "dsb ish\n\t"
         "isb\n"
         "_vel1_tlbi_all_hvc:\n\t"
         "hvc #0x102\n\t"
         "b .\n"
         "_vel1_blob_end:\n\t"
         ".text" );
#endif
