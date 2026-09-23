// SPDX-License-Identifier: MIT
//
// gmm — guest memory manager prototype, native/dryrun half.
// See ../DESIGN-guest-memory-manager.md (design doc) for the full rationale. This header is the API of design
// section 1, plus a small amount of test-support surface that the design calls for (N2/N4) but does not itself
// specify a mechanism for — those additions are marked "TEST SUPPORT" below and are also called out in
// gmm/README.md.
//
// C11, no hv_*/Hypervisor.framework anywhere in this file or gmm.c/gmm_walk.c. The backend (stage-2 map/unmap,
// TLB maintenance) is a function-pointer table (gmm_backend_t) so the SAME gmm.c serves both a live vCPU harness
// (gmm_vm.c, not built by this task) and native tests, which install recording fake backends.
#pragma once
#include <stddef.h>
#include <stdint.h>
// G7/N11: mach_port_t only (a memory-entry send right) -- Mach IPC, not Hypervisor.framework; still no hv_* here.
#include <mach/mach_types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gmm gmm_t;
typedef struct gmm_section gmm_section_t;

// ---------------------------------------------------------------------------------------------------------------
// Backend: live = hv_*, native = recording fakes. §1.
typedef struct {
  // Stage-2 map/unmap a 16K host chunk — either one private-region backing chunk (lazily, on its first 4K
  // commit) or one constituent chunk of a section anchor (eagerly, all of them at gmm_section_create()). ALWAYS
  // exactly 16K, ALWAYS R|W|X (perm is carried for the live backend's HV_MEMORY_* translation and for the
  // backend's own bookkeeping/logging; gmm always passes GMM_S2_RWX, so this parameter is not, in the current
  // design, used to restrict anything — stage-1 does all 4K protection, §2).
  // FAST MAPPING (2026-09-23): the thin API with cfg.s2_run_chunks > 1 passes a multiple of 16K (a whole run, one
  // contiguous host range at one contiguous IPA range), and its s2_unmap may name a SUB-RANGE of one prior s2_map
  // (split policy). A non-zero return from such a sub-range unmap is not fatal: gmm retains the chunks (see
  // GMM_CFG_S2_REMAP). Every other caller and every legacy path keeps the 16K / exact-match contract below.
  uint32_t (*s2_map)(void *host, uint64_t ipa, size_t sz, int perm);
  uint32_t (*s2_unmap)(uint64_t ipa, size_t sz);  // exactly one prior s2_map with the same (ipa, sz) -- or, for
                                                  // thin runs, a sub-range of one (see above)
  // TLB maintenance for `n` VAs (or the whole address space if all!=0, ignoring va/n). Returns after the
  // maintenance vCPU's `dsb ishst; tlbi ...; dsb ish; isb; hvc HC_DONE` sequence completes (§2, "who executes the
  // TLBI") — i.e. this call is SYNCHRONOUS: by the time it returns, no future access anywhere can observe the
  // pre-invalidation translation. Native fakes may simply record the call; gmm_test.c's N8 fake additionally
  // flushes its emulated per-vCPU software TLBs so the stress test can prove no access ever reaches a stale IPA.
  int (*tlbi_sync)(void *ctx, const uint64_t *va, size_t n, int all);
  void *ctx;
  // G7/N11 API DEVIATION (added 2026-09-23, see gmm/README.md's "N11" section and
  // ../DESIGN-guest-memory-manager.md's "G7"): stage-2 map for FOREIGN memory (another process's named-entry-
  // backed anonymous page, e.g. a wineserver msync page), as opposed to s2_map's own-allocated chunks. Appended
  // as the LAST field so every pre-existing positional initializer in this tree ({s2_map, s2_unmap, tlbi_sync,
  // ctx}, gmm_test.c's g_std_backend/g_n8_backend) needed only a trailing `, NULL` added (found while building
  // N11 -- this file's -Wextra -Werror turns -Wmissing-field-initializers into a hard error on the OLD 4-element
  // form now that there are 5 fields; a designated initializer, as G6's gmm_vm.c already uses throughout, would
  // not have needed even that). NOTHING in
  // gmm.c's commit/section paths calls this — it is reached ONLY through gmm_foreign_s2_map()'s wrapper below,
  // which is itself not wired into any mutating gmm_* call; a live gmm_vm.c backend may leave it NULL until G7 is
  // actually pursued (see DESIGN's "Decision (2026-09-23)": G7's vCPU runs are held).
  uint32_t (*s2_map_foreign)(void *host, uint64_t ipa, size_t sz, int perm);
} gmm_backend_t;

#define GMM_S2_R 1
#define GMM_S2_W 2
#define GMM_S2_X 4
#define GMM_S2_RWX (GMM_S2_R | GMM_S2_W | GMM_S2_X)

typedef struct {
  uint64_t alias_base;  // 0x4_0000_0000 in the proven designs; 0 disables the low-4GiB dual-alias rule entirely
  uint64_t ipa_lo, ipa_hi;      // data-chunk IPA allocation range (bump + free list), 16K-granular
  uint64_t pt_pool_ipa;         // IPA base of the caller-owned, caller-s2-mapped page-table pool
  void *pt_pool_host;           // host pointer to that pool (mmap'd PROT_READ|WRITE|MAP_ANON by the caller)
  size_t pt_pool_sz;            // multiple of 4096
  unsigned t0sz;                // TCR_EL1.T0SZ for TTBR0 (16 or 25 in the proven tables; general in the walker)
  // G7/N11 API DEVIATION, appended at the end (designated initializers elsewhere in this tree are unaffected;
  // this also keeps any stray positional gmm_config_t initializer, if one existed, compiling). The dedicated IPA
  // window gmm_foreign_s2_map()'s wrapper will restrict any future s2_map_foreign() call to. Equal values (the
  // zero-initialized default) mean "no foreign window configured" -- every foreign IPA is then refused.
  uint64_t foreign_ipa_lo, foreign_ipa_hi;
  // Wine M1 (2026-09-23), appended: GMM_CFG_* below. 0 (the zero-initialized default) = the M1 policy: eager
  // TLBI on every change to a valid descriptor, no paranoid re-checks.
  unsigned flags;
  // FAST MAPPING (2026-09-23, appended; DESIGN-guest-memory-manager.md "Fast mapping"): the most 16K chunks the
  // thin API may put into ONE backend->s2_map call. A run is a maximal set of VA-contiguous chunks that gain their
  // first committed page in the same call, lie in one host VM region, and get one contiguous IPA range. 0 or 1 =
  // one s2_map per 16K chunk (the Wine M1 behaviour, and what every pre-existing caller gets). The legacy region
  // API (gmm_commit/gmm_section_create) is unaffected: it always maps per chunk.
  unsigned s2_run_chunks;
} gmm_config_t;

// gmm_config_t.flags.
enum {
  // LEGACY TLBI POLICY (off by default; kept for comparison runs such as gmm_vm's g=8l calibration and N6). With
  // this flag a permission RAISE on a valid descriptor (RO->RW, write-watch/SMC overlay cleared, PXN 1->0) is
  // written WITHOUT a TLBI; a vCPU still holding the old, stricter entry takes a spurious permission fault, and
  // gmm_fault() answers GMM_F_RETRY_LOCAL_TLBI (the guest vector is expected to `tlbi vale1` locally and retry).
  // Without the flag (the default, "eager"): every change to a currently-valid descriptor is shot down before the
  // call returns, raises included; only invalid->valid stays TLBI-free (never cached, proven live in G5b), and
  // gmm_fault() never returns GMM_F_RETRY_LOCAL_TLBI. Reason for the switch: Wine's M1 vector forwards every
  // fault to the host, and the host cannot execute a TLBI on the faulting vCPU (fex-side-reply-m1 §1c item 1).
  GMM_CFG_LAZY_RAISE_TLBI = 0x1,
  // PARANOID ORDERING CHECK (thin/identity API only): re-run the caller-backing guard on a chunk right before
  // every stage-2 unmap of it. If the caller changed or removed its host mapping while gmm still had the chunk
  // stage-2 mapped (i.e. broke the "gmm hook first, host mapping change after" rule, README "Wine M1 fixes"),
  // gmm aborts instead of unmapping and freeing the IPA. Costs one mach_vm_region per 16K unmap. On in tests.
  GMM_CFG_PARANOID = 0x2,
  // FAST MAPPING, revoke policy for a chunk inside a multi-chunk stage-2 run (only matters with s2_run_chunks > 1).
  // Without this flag (the default, "split"): hv_vm_unmap of just the emptied sub-range. If the backend REFUSES a
  // sub-range unmap, gmm does not abort: the emptied chunks stay stage-2 mapped ("retained": gmm_vm_s2_mapped()
  // keeps answering 1, their descriptors are invalid and shot down, their IPA stays allocated), no sub-range unmap
  // is ever attempted again by this gmm_t (gmm_s2_stats_t.split_refused), and they are released with the whole run
  // once every chunk of it is empty. With this flag ("remap", the fallback if HVF refuses splits): the surviving
  // chunks' valid descriptors are invalidated and shot down together with the revoked ones, the whole run is
  // unmapped (an exact unmap of one prior map call), the survivors are re-mapped at the SAME IPAs as one map call
  // per contiguous piece, and their descriptors are restored (invalid->valid: no TLBI). A vCPU touching a survivor
  // in that window takes an ordinary stage-1 fault; gmm_vm_fault() blocks on the gmm mutex and answers RETRY.
  GMM_CFG_S2_REMAP = 0x4,
};

// Error returns (every int-returning mutator; 0 = success). GMM_EINVAL (-1) is the historical "anything wrong"
// value and is still what every argument/state error returns; the others were added for Wine M1 so a caller can
// tell resource exhaustion from a bug. Every mutator that returns one of these has changed NOTHING observable:
// no descriptor, vprot, chunk refcount, stage-2 mapping or region record (tables allocated from the PT pool
// before an exhaustion is detected may remain allocated -- still-invalid, reusable, and never freed by design).
enum {
  GMM_EINVAL = -1,
  GMM_ENOPT = -2,    // page-table pool exhausted
  GMM_ENOIPA = -3,   // IPA range exhausted
  GMM_ENOMEM = -4,   // host allocation failed (gmm-owned backing only)
  GMM_ES2 = -5,      // backend->s2_map failed; everything this call mapped was unmapped again, and the failed
                     // chunk's IPA (and, for gmm-owned memory, its host chunk) is quarantined forever -- never
                     // reused, never freed -- because a failed map may still be partly mapped (G5 review rule)
  GMM_EGUARD = -6,   // caller-provided backing failed the backing guard (identity/thin API only)
  GMM_EEXIST = -7,   // range overlaps something it may not (a legacy region, the alias window, a committed page)
};

// TEST/CALLER SUPPORT: allocates memory that will pass gmm's backing guard (§2: VM_MAKE_TAG'd, non-executable
// anonymous memory; gmm_init() enforces this on cfg->pt_pool_host exactly as gmm.c enforces it on its own
// private-chunk and section-chunk allocations, via the SAME check — so the caller-supplied PT pool gets the same
// "never a MAP_JIT/driver page" safety property described in CLAUDE.md's Hard Safety Rules). This is the only
// legitimate way to produce a pt_pool_host gmm_init() will accept; the tag value itself is private to gmm.c.
void *gmm_alloc_backing(size_t sz);
void gmm_free_backing(void *p, size_t sz);
// TEST SUPPORT (N7 only): the mmap fd-argument (VM_MAKE_TAG(tag)) gmm_alloc_backing() uses. gmm_alloc_backing()
// itself only ever requests PROT_READ|PROT_WRITE, so it cannot produce a mapping that is BOTH correctly tagged
// AND executable — which N7 needs, to test the backing guard's executable check in isolation from its tag check.
// (On this platform mprotect()-ing an already-VM_MAKE_TAG'd R|W mapping to add PROT_EXEC is refused by the
// kernel with EACCES regardless of gmm — found while writing N7, see gmm/README.md — so the only way to get a
// correctly-tagged executable mapping at all is PROT_EXEC at mmap() time, which needs this flag value.)
int gmm_debug_tag_flag(void);

// ---------------------------------------------------------------------------------------------------------------
// G7/N11 (host-only): foreign memory -- a page another process owns and handed us via a Mach named memory entry
// (a wineserver msync page is the motivating case; see ../DESIGN-guest-memory-manager.md's "G7"). NONE of these
// touch hv_*/Hypervisor.framework; NONE of them are called by any other gmm_* function. `gmm` is accepted by
// gmm_foreign_map/gmm_foreign_s2_map for API symmetry with the rest of this header and so a future caller can be
// handed one object that owns both a normal and a foreign mapping, but the foreign registry itself (which only
// gmm_foreign_map() fills, and only gmm_foreign_backing_check()/gmm_foreign_s2_map() consult) is process-global,
// not gmm_t-scoped -- deliberately: the memory a foreign entry names is not this gmm_t's to own or free, so there
// is nothing gmm_t-lifetime-scoped about knowing it was legitimately obtained.
//
// gmm_foreign_map: mach_vm_map()s `entry` (a receive-side memory-entry send right, as
// mach_make_memory_entry_64() hands out) at a fresh address, VM_MAKE_TAG(251) (a SEPARATE tag from
// GMM_VM_TAG=250's own-allocated memory -- 251 must never satisfy gmm_backing_check(), see N11's "normal guard
// rejects tag 251" case), cur=max=VM_PROT_READ|VM_PROT_WRITE (this alone, not our own mmap's RWX, is what the
// design's G7 section calls "stricter than our mmap's RWX"), VM_INHERIT_NONE (exactly wine's client-side
// ntdll/unix/msync.c:586-588 shape). On success, `*out` is registered so it -- and ONLY it, by exact (host, sz)
// -- can later pass gmm_foreign_backing_check(). Does not itself validate the entry's backing; that is
// gmm_foreign_backing_check()'s job, deliberately kept separate so a test can map something bad and then observe
// the guard reject it.
int gmm_foreign_map(gmm_t *gmm, mach_port_t entry, size_t sz, void **out);
// gmm_foreign_backing_check: the G7 guard (../DESIGN-guest-memory-manager.md's "Guard" paragraph), separate from
// gmm_backing_check() (§2) and reached only via gmm_foreign_s2_map() below (no commit/section path calls it).
// ALL of: [p, p+sz) is exactly one mach_vm_region, starting exactly at p; sz == 16384 (gmm's chunk granularity --
// a 32K or smaller region is refused, not truncated or rounded); VM_REGION_EXTENDED_INFO's user_tag == 251;
// neither VM_REGION_BASIC_INFO_64's protection nor max_protection carries VM_PROT_EXECUTE; external_pager == 0
// (refuses a file-backed entry, which sets it to 1 -- measured); share_mode == the value measured in N11a
// (SM_TRUESHARED, stable over 5 repeated in-process runs -- see gmm/README.md's "N11" section for the numbers
// and for what a file-backed/32K-region entry measures instead); not VM_PURGABLE_VOLATILE/_EMPTY (a
// mach_vm_purgable_control() failure, e.g. KERN_INVALID_ARGUMENT for ordinary non-purgeable memory -- the
// expected shape here, also measured -- is treated as "not purgeable", i.e. a pass, not a rejection); and
// (host, sz) is present in the registry gmm_foreign_map() fills. Returns 0 if EVERY check passes, -1 otherwise.
int gmm_foreign_backing_check(void *p, size_t sz);
// gmm_foreign_s2_map: the "gmm-side wrapper" the design's G7 section requires around backend->s2_map_foreign --
// refuses any perm other than GMM_S2_R (never W or X for foreign memory, per G7's "Stage-2 READ only"), refuses
// any [ipa, ipa+sz) outside [cfg.foreign_ipa_lo, cfg.foreign_ipa_hi) (refuses everything if that window is
// unconfigured, i.e. foreign_ipa_lo == foreign_ipa_hi), and re-runs gmm_foreign_backing_check(host, sz) itself
// (a caller must not be able to skip the guard by calling this directly with an unchecked host pointer). Only
// once every check passes does it call backend->s2_map_foreign() -- which no other gmm_* function does, so this
// wrapper is the ONLY path by which that hook can ever fire, and only when a caller (a test, here) invokes it
// explicitly; it is not reachable from gmm_commit()/gmm_section_create() or any other mutating call.
int gmm_foreign_s2_map(gmm_t *gmm, void *host, uint64_t ipa, size_t sz, int perm);
// TEST SUPPORT (N11 only): gmm_debug_tag_flag()'s counterpart for the FOREIGN tag (251) -- the mmap fd-argument
// (VM_MAKE_TAG(251)) N11a needs to construct an adversarial "tag-251 but never went through gmm_foreign_map(), so
// not in the registry" mapping directly, without needing gmm.c's tag value to stop being private to it.
int gmm_debug_foreign_tag_flag(void);

int gmm_init(gmm_t **out, const gmm_config_t *cfg, const gmm_backend_t *backend);
void gmm_destroy(gmm_t *gmm);  // TEST SUPPORT: not in §1's listed API, but every native test needs to tear down
                                // cleanly under ASan (free the PT-pool suballocator bookkeeping, the region array,
                                // the trace log, the IPA free list) between cases without leaking. The live harness
                                // has no equivalent need (the process exits); gmm_vm.c is free to ignore it.
uint64_t gmm_ttbr0(gmm_t *gmm);

// ---------------------------------------------------------------------------------------------------------------
// Page protection. Independent numeric encoding chosen to match the public Win32 PAGE_* values bit-for-bit (so a
// future wine integration can pass its DWORD protect flags straight through) WITHOUT copying any wine source
// (per CLAUDE.md "No Apple-binary redistribution" / the design's "do not copy wine code (LGPL)").
enum {
  GMM_PAGE_NOACCESS = 0x01,
  GMM_PAGE_READONLY = 0x02,
  GMM_PAGE_READWRITE = 0x04,
  GMM_PAGE_WRITECOPY = 0x08,
  GMM_PAGE_EXECUTE = 0x10,
  GMM_PAGE_EXECUTE_READ = 0x20,
  GMM_PAGE_EXECUTE_READWRITE = 0x40,
  GMM_PAGE_EXECUTE_WRITECOPY = 0x80,
  GMM_PAGE_GUARD = 0x100,        // modifier, OR'd onto one of the above
  GMM_PAGE_NOCACHE = 0x200,      // modifier; tracked but does not affect the PTE encoder in this prototype
  GMM_PAGE_WRITECOMBINE = 0x400, // modifier; ditto
  // gmm-specific, not a Win32 bit: forces PXN=0 on a page whose base protection is NOT PAGE_EXECUTE* (e.g. a
  // READWRITE page FEX's code cache lives in). WINE M1 / D1 RULE (2026-09-23): every PAGE_EXECUTE* page already
  // gets PXN=0 -- FEX and arm64ec code run natively at EL1, so an executable Windows page must be fetchable at
  // EL1 (x86 code pages included, as on Windows on ARM; Wine's arm64ec map could tighten that later). Before M1 the
  // rule was "PXN=1 unless ARM64CODE". UXN stays 1 always (nothing runs at EL0).
  GMM_PAGE_ARM64CODE = 0x800,
};
#define GMM_PAGE_PROT_MASK 0xFFu       // the base PAGE_* value without modifiers
#define GMM_PAGE_MOD_MASK 0xF00u       // GUARD | NOCACHE | WRITECOMBINE | ARM64CODE

// gmm_reserve flags.
enum {
  GMM_RESERVE_LOW4G = 0x1,  // <4GiB region; mirrored at [alias_base, alias_base+4G) per the address rule (§1)
};

// gmm_set_overlay bits — software write-tracking, never visible to x86 code, forced via AP[2]=1 (RO) at stage 1.
enum {
  GMM_OVERLAY_WRITEWATCH = 0x1,  // WRITE_WATCH: one-shot: first write after the overlay is set clears it
  GMM_OVERLAY_SMC = 0x2,         // self-modifying-code trap: NOT one-shot; caller must gmm_set_overlay(clr=SMC)
                                  // again once it has finished handling the write (I-cache maintenance etc).
};

int gmm_reserve(gmm_t *gmm, uint64_t va, size_t sz, unsigned flags);        // 64K-aligned; no valid PTEs
int gmm_commit(gmm_t *gmm, uint64_t va, size_t sz, uint32_t page_prot);     // 4K granular
int gmm_decommit(gmm_t *gmm, uint64_t va, size_t sz);
int gmm_release(gmm_t *gmm, uint64_t alloc_base);
int gmm_protect(gmm_t *gmm, uint64_t va, size_t sz, uint32_t prot, uint32_t *old);

int gmm_section_create(gmm_t *gmm, size_t sz, gmm_section_t **out);
// API DEVIATION from the design's §1 signature (added for G6, ../DESIGN-guest-memory-manager.md §3 row G6, see
// gmm/README.md's "API deviations" section): a `flags` parameter, taking GMM_RESERVE_LOW4G with the IDENTICAL
// meaning gmm_reserve() already gives it -- `va` must be a canonical <4GiB address, and gmm mirrors this view's
// PTEs at alias_base+va too (write_leaf_both, gmm.c), exactly like a low4g PRIVATE region. Without this, there was
// no way to place a section view's second (high) alias inside [alias_base, alias_base+4G) at all: the pre-existing
// alias-window-overlap check unconditionally refused ANY view touching that window, low4g or not (the window is
// reserved exclusively for automatic low4g mirrors, never a manually-placed view) -- a real gap, not a style
// choice, found while building G6 (gmm_map_view was never called by G1-G5, so it was untested code, per the task's
// "implement it test-first" instruction; see N10 in gmm_test.c). flags=0 preserves the exact previous behaviour
// (the view must lie entirely outside the alias window) for a non-aliased, independent view like G6's "v2".
int gmm_map_view(gmm_t *gmm, gmm_section_t *section, uint64_t off, uint64_t va, size_t sz, uint32_t prot,
                  unsigned flags);
int gmm_unmap_view(gmm_t *gmm, uint64_t va);
// TEST/CALLER SUPPORT (added for G6, not in the design's §1 list): a raw host pointer into a section's own
// backing anchor, by byte offset -- independent of any view/region. Needed so a caller (gmm_vm.c's G6 harness) can
// (a) build a SECOND, host-only view of the anchor via mach_vm_remap(copy=FALSE) (../DESIGN-guest-memory-manager.md
// §2 "Sections": "host views are mach_vm_remap(copy=FALSE) of the anchor, never given to hv_vm_map"), which needs
// a source address, and (b) read/write the anchor directly, independent of and prior to any gmm_map_view() call,
// for a host-side coherence check. Returns NULL if `off >= section`'s size (as passed to gmm_section_create()).
void *gmm_section_host_ptr(gmm_section_t *section, uint64_t off);

// MEMORY_BASIC_INFORMATION-shaped query result (field names chosen to match the Win32 struct's meaning, not its
// exact type widths — again no wine/Win32 header copied).
typedef struct {
  uint64_t base_address;
  uint64_t allocation_base;
  uint32_t allocation_protect;
  uint64_t region_size;   // bytes from base_address to the next state/protect change, or region end
  uint32_t state;         // GMM_STATE_*
  uint32_t protect;       // current effective page_prot (GMM_PAGE_* bits) of base_address's page
  uint32_t type;          // GMM_TYPE_*
} gmm_mbi_t;
enum { GMM_STATE_FREE = 0, GMM_STATE_RESERVE = 1, GMM_STATE_COMMIT = 2 };
enum { GMM_TYPE_NONE = 0, GMM_TYPE_PRIVATE = 1, GMM_TYPE_MAPPED = 2 };

int gmm_query(gmm_t *gmm, uint64_t va, gmm_mbi_t *out);
void *gmm_host_ptr(gmm_t *gmm, uint64_t va);  // NULL if va is not currently committed
int gmm_set_overlay(gmm_t *gmm, uint64_t va, size_t sz, unsigned set, unsigned clr);

typedef enum { GMM_F_RETRY, GMM_F_RETRY_LOCAL_TLBI, GMM_F_GUARD, GMM_F_AV, GMM_F_BUG } gmm_fault_t;
// From an HC_EXC exit (§0: guest self-relays ESR_EL1/FAR_EL1/ELR_EL1 for its own EL1 fault). ESR must be the
// guest's own ESR_EL1, never an HVF exit syndrome (a stage-2 abort is a broken gmm invariant, not a guest fault).
// Wine M1 fixes: translation faults at ANY level (DFSC 0x04-0x07) are classified -- a reserved range whose L0-L2
// tables don't exist yet faults at level 0-2 and is a normal AV/GUARD/RETRY case, not GMM_F_BUG; only memory
// aborts (EC 0x20/0x21/0x24/0x25) with a valid FAR (ESR.FnV=0) and a translation or level-3 permission DFSC are
// classified, everything else (access-flag, address-size, block-level permission, TLB conflict, ...) is
// GMM_F_BUG. GMM_F_RETRY_LOCAL_TLBI is returned only under GMM_CFG_LAZY_RAISE_TLBI.
gmm_fault_t gmm_fault(gmm_t *gmm, uint64_t far, uint64_t esr);

// ---------------------------------------------------------------------------------------------------------------
// WINE M1 THIN API ("identity backing"): the caller's view tree (Wine's virtual.c) is the ONLY authority for
// Windows semantics. gmm keeps only what the hardware needs: the stage-1 descriptors, a 16K chunk table
// {IPA, stage-2 mapped, which 4K pages are committed}, the IPA allocator, and the revocation/TLBI order. No region
// tree, no per-page Win32 protection, no guard/write-watch state (Wine turns those into the stage-1 states below).
//
// Address rule: the CALLER provides the backing AT the guest VA (host VA == guest VA, the shape step3b's
// GuestMirror::MapHostPage proved in every 3a-3d and M:N run). The IPA is NEVER the VA: every chunk gets an IPA
// from gmm's own allocator [cfg.ipa_lo, cfg.ipa_hi) (use a 40-bit IPA space: macOS VAs reach 47 bits).
//
// Ownership: gmm NEVER mmaps, munmaps, mprotects or zeroes caller memory. It only stage-2 maps a 16K host page
// (on the first commit of any 4K page in it) and stage-2 unmaps it (when the last committed 4K page in it is
// decommitted), after the revocation ladder: descriptors invalid -> one batched TLBI -> hv_vm_unmap -> IPA freed.
// FAST MAPPING (2026-09-23): with cfg.s2_run_chunks > 1, contiguous newly-committed chunks share ONE stage-2 map
// (a "run record", gmm_vm_s2_run below) and a revoke inside a run is a sub-range unmap, or -- if the backend
// refuses it -- the chunk is retained (still mapped, gmm_vm_s2_mapped() keeps answering 1); see GMM_CFG_S2_REMAP.
// The caller changes its host mapping (munmap, MAP_FIXED, madvise, mprotect) only AFTER the gmm call that
// revokes it has returned, and only for 16K host pages gmm_vm_s2_mapped() reports as unmapped (README "Wine M1
// fixes", ordering rules).
//
// Backing requirements, checked by the guard before EVERY stage-2 map (abort-free: a failure returns GMM_EGUARD
// with nothing mapped): the whole 16K host page is mapped, VM_MAKE_TAG(250) (gmm_debug_tag_flag() gives the mmap
// fd-argument), current protection exactly READ|WRITE (no EXECUTE, not PROT_NONE, not read-only), not file-backed
// (external_pager == 0). Allocate with mmap(va, sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON|MAP_FIXED,
// VM_MAKE_TAG(250), 0) and never mprotect it while stage-2 mapped.
//
// Coexistence: the thin API and the legacy region API may share one gmm_t (one set of tables, one IPA allocator);
// their ranges must not overlap (GMM_EEXIST), and neither may touch the low-4GiB alias window
// [alias_base, alias_base+4G) when alias_base != 0. The thin API never writes an alias (it is for 64-bit memory;
// low-4GiB pages keep using gmm_reserve(GMM_RESERVE_LOW4G), whose backing gmm owns).

// Per-4K target stage-1 state. A page is "committed" (its 16K chunk stays stage-2 mapped) iff GMM_S1_COMMIT is
// set; its descriptor is valid iff it is committed AND has at least one access bit. W implies R (AArch64 has no
// write-only). X gives PXN=0 (the D1 rule: FEX and arm64ec run natively at EL1) and implies R (at EL1 a valid
// descriptor is always readable). UXN is always 1. Access bits without GMM_S1_COMMIT are GMM_EINVAL.
// How Wine maps its vprot byte: VPROT_COMMITTED -> COMMIT; VPROT_READ -> R; VPROT_WRITE|VPROT_WRITECOPY -> R|W;
// VPROT_EXEC -> X|R; VPROT_WRITEWATCH clears W; VPROT_GUARD (and NOACCESS) -> COMMIT with no access bits.
enum { GMM_S1_R = 0x1, GMM_S1_W = 0x2, GMM_S1_X = 0x4, GMM_S1_COMMIT = 0x8 };
#define GMM_S1_NONE 0u                                       // reserved / decommitted: invalid, chunk may unmap
#define GMM_S1_RO (GMM_S1_COMMIT | GMM_S1_R)
#define GMM_S1_RW (GMM_S1_COMMIT | GMM_S1_R | GMM_S1_W)
#define GMM_S1_RX (GMM_S1_COMMIT | GMM_S1_R | GMM_S1_X)
#define GMM_S1_RWX (GMM_S1_COMMIT | GMM_S1_R | GMM_S1_W | GMM_S1_X)
#define GMM_S1_NOACCESS GMM_S1_COMMIT                        // committed but invalid (guard, NOACCESS)

// gmm_vm_range_set: set the target state of every 4K page in [va, va+size) (va, size 4K-aligned). Commit,
// protect, guard arm/clear, write-watch arm/clear and decommit are all this one call. Order inside the call:
// (A) validate and reserve every resource (IPAs, PT tables, backing guard) -- any failure returns an error with
// nothing changed; (B) stage-2 map every chunk that gains its first committed page; (C) write the descriptors;
// (D) ONE batched tlbi_sync for every descriptor that WAS valid and changed (eager policy; invalid->valid needs
// none); (E) stage-2 unmap and free the IPA of every chunk left with no committed page. Returns 0 or GMM_E*.
int gmm_vm_range_set(gmm_t *gmm, uint64_t va, size_t size, unsigned s1);
// Same, with a per-4K target byte (npages entries). This is the one Wine's mprotect_range hook wants: it passes
// the per-4K vprot bytes, NOT the 16K union mprotect_range folds them into for host mprotect.
int gmm_vm_range_set_pages(gmm_t *gmm, uint64_t va, size_t npages, const uint8_t *s1);
// gmm_view_map: the map_view hook. `host_backing` must equal (void *)va (identity backing; anything else is
// GMM_EINVAL -- the parameter exists so a non-identity backing can be added later without an API break). Checks
// that no page of the range is already committed (GMM_EEXIST) and applies `s1` to every page (usually
// GMM_S1_NONE for a reservation, or the committed protection for MEM_RESERVE|MEM_COMMIT). va and size may be
// 4K-granular; two views may share a 16K host page (the chunk stays mapped while either has a committed page).
int gmm_view_map(gmm_t *gmm, uint64_t va, size_t size, const void *host_backing, unsigned s1);
// gmm_view_unmap: the delete_view hook. Every page of the range becomes GMM_S1_NONE (full revocation ladder);
// returns once no vCPU can reach the range and every 16K host page wholly inside it is stage-2 unmapped. A host
// page shared with another view that still has a committed page stays stage-2 mapped (gmm_vm_s2_mapped()).
int gmm_view_unmap(gmm_t *gmm, uint64_t va, size_t size);
// 1 if the 16K host page containing va is stage-2 mapped (the caller must not change its host mapping), else 0.
int gmm_vm_s2_mapped(gmm_t *gmm, uint64_t va);

// FAST MAPPING (2026-09-23): stage-2 run bookkeeping of the thin API, for callers that want to observe it (the
// G12 harness) and for tests. A "run record" is one live stage-2 mapping: a contiguous IPA range <-> the
// contiguous caller host range at the same VA, established by exactly one backend->s2_map call and possibly
// trimmed since by sub-range unmaps (split policy). Every chunk in a record is stage-2 mapped (records have no
// holes). gmm_vm_s2_run: 1 and the record containing va (its first VA, its IPA, its size in bytes), else 0.
int gmm_vm_s2_run(gmm_t *gmm, uint64_t va, uint64_t *run_va, uint64_t *run_ipa, uint64_t *run_bytes);
typedef struct {
  uint64_t map_calls;        // backend->s2_map calls made by the thin API (all sizes)
  uint64_t map_bytes;        // bytes mapped by those calls
  uint64_t unmap_calls;      // backend->s2_unmap calls made by the thin API that succeeded
  uint64_t unmap_exact;      // ... whose range was exactly one prior s2_map call's range
  uint64_t unmap_sub;        // ... whose range was a strict sub-range of one prior s2_map call's range (split)
  uint64_t unmap_refused;    // sub-range unmaps the backend refused (split policy): those chunks were retained
  uint64_t remaps;           // whole-run remaps (GMM_CFG_S2_REMAP)
  uint64_t records;          // current number of run records
  uint64_t mapped_chunks;    // current number of stage-2 mapped thin chunks (retained ones included)
  uint64_t retained_chunks;  // current number of stage-2 mapped thin chunks with no committed page
  int split_refused;         // sticky: the backend refused a sub-range unmap; gmm never attempts one again
} gmm_s2_stats_t;
void gmm_vm_s2_stats(gmm_t *gmm, gmm_s2_stats_t *out);
// TEST SUPPORT: IPA of the stage-2 mapped thin chunk containing va, or UINT64_MAX.
uint64_t gmm_vm_chunk_ipa(gmm_t *gmm, uint64_t va);
// TEST SUPPORT: how many 16K IPA chunks the allocator can still hand out (free extents + the untouched top).
uint64_t gmm_debug_ipa_available(gmm_t *gmm);
// TEST SUPPORT: full internal consistency check, under the mutex. Run records sorted, disjoint in VA and IPA, and
// without holes; each chunk of each record present in the chunk table with ipa == record.ipa + offset, and every
// chunk-table entry inside exactly one record; the IPA free list sorted, coalesced, inside [ipa_lo, bump) and
// disjoint from every record and every legacy chunk/section IPA; every valid thin descriptor points at its chunk's
// IPA + offset with that page's committed bit set. Returns 0, or the number of violations (each printed).
int gmm_debug_check(gmm_t *gmm);
// Identity backing: returns (void *)va if the 4K page at va is committed through the thin API, else NULL.
// (gmm_host_ptr() answers the same for thin pages, so existing callers work on either kind of memory.)
void *gmm_vm_host_ptr(gmm_t *gmm, uint64_t va);

// gmm_vm_fault: the thin API's fault question -- "is the access this ESR describes permitted by the stage-1
// descriptor as it is NOW?". gmm keeps no Windows state, so it never decides guard/write-watch/stack growth:
//   GMM_VF_RETRY  -- the live descriptor now permits the access (a concurrent range_set on another thread won the
//                    race; with the eager policy its TLBI has already completed): resume the vCPU unchanged.
//   GMM_VF_WINE   -- not permitted now (translation fault at any level, or a permission fault the descriptor
//                    still enforces) or a non-translation abort that is the application's own (alignment):
//                    hand it to Wine (virtual_handle_fault decides guard/write-watch/stack growth; any PTE change
//                    comes back through gmm_vm_range_set; otherwise raise the exception).
//   GMM_VF_FATAL  -- a broken invariant or not a memory abort gmm can answer: EC not 0x20/0x21/0x24/0x25, FnV
//                    set (FAR invalid), access-flag / address-size / block-level permission / TLB-conflict /
//                    external abort. Never SEH.
// ESR must be the guest's ESR_EL1 as its vector saw it, never an HVF exit syndrome (a stage-2 abort exit is
// GMM_VF_FATAL by definition, and the caller must not pass it here).
typedef enum { GMM_VF_RETRY = 0, GMM_VF_WINE = 1, GMM_VF_FATAL = 2 } gmm_vfault_t;
gmm_vfault_t gmm_vm_fault(gmm_t *gmm, uint64_t far, uint64_t esr);

// ---------------------------------------------------------------------------------------------------------------
// gmm_walk: the oracle. Declared fully in gmm_walk.h (a standalone, gmm_t-independent AArch64 stage-1 walker used
// directly by N2/N3/N8, plus the gmm_t-bound convenience wrapper gmm_walk() below).
#include "gmm_walk.h"
// gmm_walk() is deliberately lock-free (it walks the live tables directly, exactly as hardware would — that is
// the point of using it as N8's oracle against concurrent mutators) EXCEPT for its address-rule dealiasing step,
// which does consult gmm's region array without the mutex. That array can be realloc()'d by a concurrent
// gmm_reserve()/gmm_map_view()/gmm_release()/gmm_unmap_view() on another thread. A concurrent-access test (N8)
// that wants a genuinely race-free, lock-free oracle read must call gmm_walk_raw() directly (gmm_ttbr0(gmm) as
// ttbr0_ipa, the same t0sz, and a pre-canonicalised va — i.e. resolve which alias you mean up front, the way
// FEX/wine would already know which VA it formed) rather than this wrapper.
int gmm_walk(const gmm_t *gmm, uint64_t va, gmm_xlat_t *out);

// ---------------------------------------------------------------------------------------------------------------
// TEST SUPPORT (not in the design's §1 API list): an always-on internal event trace, used by N4's revocation-order
// checker and available to any other test. Recording the trace costs one dynamic-array append per event; there is
// no live-path equivalent need (gmm_vm.c's maintenance-vCPU discipline is already logged the rung_vm.c way) so
// this is harmless prototype-only surface, not a change to the live ABI.
typedef enum {
  GMM_EV_PTE_VALID,     // a.va now has a valid stage-1 descriptor (ipa = its output address)
  GMM_EV_PTE_INVALID,   // a.va now has an invalid stage-1 descriptor (ipa = the descriptor's tag, GMM_TAG_*)
  GMM_EV_TLBI,          // a tlbi_sync() call is about to be issued for a.va (ipa = n, the count folded in; only
                          // meaningful alongside the surrounding PTE_INVALID/S2_UNMAP/ZERO events, not decoded here)
  GMM_EV_ZERO,          // chunk host memory containing a.va was zeroed (decommit only)
  GMM_EV_S2_MAP,        // backend->s2_map() called for the 16K chunk containing a.va (ipa = chunk ipa)
  GMM_EV_S2_UNMAP,      // backend->s2_unmap() called for the 16K chunk containing a.va (ipa = chunk ipa)
} gmm_ev_kind_t;
typedef struct {
  gmm_ev_kind_t kind;
  uint64_t va, ipa;
  uint64_t sz;  // FAST MAPPING (appended): S2_MAP/S2_UNMAP bytes (16384 for every per-chunk call); 0 otherwise
} gmm_ev_t;
size_t gmm_trace_count(gmm_t *gmm);
gmm_ev_t gmm_trace_get(gmm_t *gmm, size_t i);
void gmm_trace_clear(gmm_t *gmm);

#ifdef __cplusplus
}
#endif
