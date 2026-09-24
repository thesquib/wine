# vcpu/ — openrosetta's vcpu_el1 and gmm (MIT), vendored

Used only by the arm64 macOS vCPU mode (`PMW_VCPU`), where every Windows thread's user-mode code runs at EL1 in a
Hypervisor.framework vCPU. Nothing here is built on any other platform: the `*_arm64.c` wrappers one level up compile to
nothing unless `__APPLE__ && __aarch64__`.

Source: fex_macos, branch `upstream-sync-20260921`, `openrosetta/hvf_proto/{vcpu_el1,gmm}/`, at two tags:
- `gmm.[ch]`, `gmm_walk.[ch]`: tag `vel1-gmm-v6` (commit `22a644a27`). v6 is the memory-op speed fix: the event trace
  is opt-in (`GMM_CFG_TRACE`, which Wine must not set), a uniform-NONE early-out, and a faster descriptor loop. v5 added
  `gmm_sect_anchor_from_fd`, which Wine doesn't use (shared-section anchors are made in `virtual.c`).
- `vcpu_el1.[ch]`, `vcpu_el1_live.c`, `vcpu_el1_blob.S`: tag `vel1-gmm-v4` (commit `94ac597c9`), identical to `v5`.
  The tree at `v6` also holds the untested `v7` draft of vcpu_el1, so these stay at `v5` until `v7` is tagged.

Releases are tags, each with an entry in openrosetta's `hvf_proto/LIBS-CHANGES.md`; re-vendor only by moving to a
tag. Files are byte-identical copies. Do not edit them here: changes go to openrosetta and are copied back.

- `vcpu_el1.[ch]`, `vcpu_el1_live.c`: vCPU creation at EL1, `vel1_run` and exit decoding, kicks (kicker thread),
  register access. Contracts D1-D17 are in `vcpu_el1.h`.
- `vcpu_el1_blob.S`: the guest vector page and the syscall / unix-call stubs. Not built directly (makedep would assemble
  it for every architecture): `vcpu_blob_arm64.c` carries the same instructions in a top-level asm block, and the
  host-only tests (`proton-darwin/mac/vcpu/tests`) check the two assemble to identical bytes.
- `gmm.[ch]`, `gmm_walk.[ch]`: guest stage-1 page tables, stage-2 mapping and the TLBI ordering. Wine uses the thin API;
  rules R1-R7 are in openrosetta's `gmm/README.md`, "Wine M1 fixes".
