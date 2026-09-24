# vcpu/ — openrosetta's vcpu_el1 and gmm (MIT), vendored

Used only by the arm64 macOS vCPU mode (`PMW_VCPU`), where every Windows thread's user-mode code runs at EL1 in a
Hypervisor.framework vCPU. Nothing here is built on any other platform: the `*_arm64.c` wrappers one level up compile to
nothing unless `__APPLE__ && __aarch64__`.

Source: fex_macos, tag `vel1-gmm-v3` (annotated tag object `60881fedf`, libraries at commit `3ffb44e74`, branch
`upstream-sync-20260921`), `openrosetta/hvf_proto/{vcpu_el1,gmm}/`. v3 changed `gmm.[ch]` (section aliasing:
`gmm_sect_create` / `gmm_view_alias` / `gmm_sect_destroy`, rules R8-R12) and only a comment in `vcpu_el1.h`; the other
files are unchanged from `vel1-gmm-v2` (`c224d7cad`). Releases are tags, each with an entry in openrosetta's
`hvf_proto/LIBS-CHANGES.md`; re-vendor only by moving to a tag. Files are byte-identical copies. Do not edit them here:
changes go to openrosetta and are copied back.

- `vcpu_el1.[ch]`, `vcpu_el1_live.c`: vCPU creation at EL1, `vel1_run` and exit decoding, kicks (kicker thread),
  register access. Contracts D1-D17 are in `vcpu_el1.h`.
- `vcpu_el1_blob.S`: the guest vector page and the syscall / unix-call stubs. Not built directly (makedep would assemble
  it for every architecture): `vcpu_blob_arm64.c` carries the same instructions in a top-level asm block, and the
  host-only tests (`proton-darwin/mac/vcpu/tests`) check the two assemble to identical bytes.
- `gmm.[ch]`, `gmm_walk.[ch]`: guest stage-1 page tables, stage-2 mapping and the TLBI ordering. Wine uses the thin API;
  rules R1-R7 are in openrosetta's `gmm/README.md`, "Wine M1 fixes".
