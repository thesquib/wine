# vcpu/ — openrosetta's vcpu_el1 and gmm (MIT), vendored

Used only by the arm64 macOS vCPU mode (`PMW_VCPU`), where every Windows thread's user-mode code runs at EL1 in a
Hypervisor.framework vCPU. Nothing here is built on any other platform: the `*_arm64.c` wrappers one level up compile to
nothing unless `__APPLE__ && __aarch64__`.

Source: fex_macos, branch `upstream-sync-20260921`, `openrosetta/hvf_proto/{vcpu_el1,gmm}/`, at two tags:
- `gmm.[ch]`: tag `vel1-gmm-v9` (fex commit `18e47cbc4`); `gmm_walk.[ch]` are unchanged since v6 (`22a644a27`). v6 is the
  memory-op speed fix (the event trace is opt-in, `GMM_CFG_TRACE`, which Wine must not set, a uniform-NONE early-out, a
  faster descriptor loop). v5 added `gmm_sect_anchor_from_fd`, which Wine doesn't use (shared-section anchors are made in
  `virtual.c`). v8 adds the WoW64 low mirror (`cfg.low_mirror_base`: the 32-bit space at `BASE + p` is also mapped at `p`).
  v9 adds `gmm_set_low_mirror`, a one-time late setter (no descriptor write, no TLBI, no `hv_*` call), because Wine only
  knows the window after `gmm_init`. With no mirror set, v9 behaves as v8 and v7 with the mirror off. Wine sets it in
  every vCPU process, after reserving the window and before committing the TEB block, and gates W5/W6 on `is_wow64()`.
- `vcpu_el1.[ch]`, `vel1_pool.c`: tag `vel1-gmm-v7` (commit `45d80033c`); `vel1_pool.h` is v9 (only its header comment differs, the
  "Signals" rules). v7 adds M:N release-on-block: [D20]
  `vel1_ctx_save`/`vel1_ctx_restore` (a thread's guest context, portable between vCPUs of one VM) and the vCPU slot
  pool `vel1_pool` (pure host C, no `hv_*` calls). The call sequence and rulings R4-R15 are in openrosetta's
  `vcpu_el1/README.md`, "M:N (release-on-block, `vel1_pool.h`)". `vcpu_el1_live.c` and `vcpu_el1_blob.S` are
  unchanged since v4.

Releases are tags, each with an entry in openrosetta's `hvf_proto/LIBS-CHANGES.md`; re-vendor only by moving to a
tag. Files are byte-identical copies. Do not edit them here: changes go to openrosetta and are copied back.

- `vcpu_el1.[ch]`, `vcpu_el1_live.c`: vCPU creation at EL1, `vel1_run` and exit decoding, kicks (kicker thread),
  register access. Contracts D1-D20 are in `vcpu_el1.h`.
- `vel1_pool.[ch]`: the vCPU slot pool (acquire/release, the release policy, the preempt/unblock monitor).
- `vcpu_el1_blob.S`: the guest vector page and the syscall / unix-call stubs. Not built directly (makedep would assemble
  it for every architecture): `vcpu_blob_arm64.c` carries the same instructions in a top-level asm block, and the
  host-only tests (`proton-darwin/mac/vcpu/tests`) check the two assemble to identical bytes.
- `gmm.[ch]`, `gmm_walk.[ch]`: guest stage-1 page tables, stage-2 mapping and the TLBI ordering. Wine uses the thin API;
  rules R1-R7 are in openrosetta's `gmm/README.md`, "Wine M1 fixes".
