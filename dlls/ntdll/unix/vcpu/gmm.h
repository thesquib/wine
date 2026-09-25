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
  // v8 (vel1-gmm-v8, WoW64): the low mirror of the THIN API. 0 = off (v7 behaviour, byte for byte). Otherwise a
  // 4 GiB-aligned, host-valid base: every thin/view descriptor for a page in W = [low_mirror_base, +4G) is also
  // written at va - low_mirror_base, and shot down there too. Must not equal or overlap [alias_base, +4G).
  // Refusals and the invariant: the "Coexistence" paragraph below, and README "v8: the low mirror (WoW64)".
  // Spec: openrosetta docs/superpowers/specs/2026-09-25-wow64-vcpu-design.md §4.
  // v9: or set later, once, with gmm_set_low_mirror (declared after gmm_vm_canon), under the same validation.
  uint64_t low_mirror_base;
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
  // gmm aborts instead of unmapping and freeing the IPA. Costs one region query per host VM entry the unmap spans. On in tests.
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
  // TEST SUPPORT (vel1-gmm-v6, 2026-09-25): record the event trace (gmm_trace_* at the end of this header). Off by
  // default: with the flag clear every trace call returns at once (no append, no GMM_PROFILE clock read). Before v6
  // the trace was always on and nothing cleared it -- 32 bytes per descriptor change for the life of the process
  // (40 MiB after five 256 MiB commit/decommit cycles) and about half of the `desc` phase (relay openrosetta
  // docs/relays/fex-side-memop-cost-2026-09-25.md). gmm_test.c and gmm_vm.c set it; WINE MUST NOT SET IT.
  GMM_CFG_TRACE = 0x8,
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
  GMM_EBUSY = -8,    // v3: gmm_sect_destroy while views of the section are registered (nothing changed)
};

// TEST/CALLER SUPPORT: allocates memory that will pass gmm's backing guard (§2: VM_MAKE_TAG'd, non-executable
// anonymous memory; gmm_init() enforces this on cfg->pt_pool_host exactly as gmm.c enforces it on its own
// private-chunk and section-chunk allocations, via the SAME check). The guard refuses a currently-executable page,
// which is all it can see: no query can distinguish a read/write MAP_JIT page from ordinary anonymous memory, so
// never MAP_JIT the memory passed here (CLAUDE.md's Hard Safety Rules) -- that is a caller rule, not something
// gmm_alloc_backing or gmm_init can check. This is the only legitimate way to produce a pt_pool_host gmm_init()
// will accept; the tag value itself is private to gmm.c.
// v3 (2026-09-24): the memory is VM_INHERIT_NONE (a fork() child never shares it), like every gmm allocation. NULL on
// failure.
void *gmm_alloc_backing(size_t sz);
void gmm_free_backing(void *p, size_t sz);
// TEST SUPPORT (N7 only): the mmap fd-argument (VM_MAKE_TAG(tag)) gmm_alloc_backing() uses. gmm_alloc_backing()
// itself only ever requests PROT_READ|PROT_WRITE, so it cannot produce a mapping that is BOTH correctly tagged
// AND executable — which N7 needs, to test the backing guard's executable check in isolation from its tag check.
// (mprotect() of a tagged R|W mapping to R|W|X is refused (EACCES) -- W^X, for any memory; to R|X it succeeds
// (N22q K6). A mapping that is tagged AND executable from the start is simplest to make with PROT_EXEC at mmap()
// time, which needs this flag value.)
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
// The caller changes its host mapping (munmap, MAP_FIXED, madvise, mprotect, minherit) only AFTER the gmm call that
// revokes it has returned, and only for 16K host pages gmm_vm_s2_mapped() reports as unmapped (README "Wine M1
// fixes", ordering rules).
//
// Backing requirements, checked by the guard before EVERY stage-2 map (abort-free: a failure returns GMM_EGUARD
// with nothing mapped): the whole 16K host page is mapped, VM_MAKE_TAG(250) (gmm_debug_tag_flag() gives the mmap
// fd-argument), current protection exactly READ|WRITE (no EXECUTE, not PROT_NONE, not read-only), not file-backed
// (external_pager == 0), and VM_INHERIT_NONE (v3; mmap's default is VM_INHERIT_COPY). Allocate with mmap(va, sz,
// PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON|MAP_FIXED, VM_MAKE_TAG(250), 0), then minherit(va, sz, VM_INHERIT_NONE)
// before the first commit (again after every MAP_FIXED replacement), and never mprotect it while stage-2 mapped.
//
// Coexistence: the thin API and the legacy region API may share one gmm_t (one set of tables, one IPA allocator);
// their ranges must not overlap (GMM_EEXIST), and neither may touch the low-4GiB alias window
// [alias_base, alias_base+4G) when alias_base != 0. The thin API never writes the legacy alias window. With
// low_mirror_base == 0 it writes no alias at all (64-bit memory; low-4GiB pages keep using
// gmm_reserve(GMM_RESERVE_LOW4G), whose backing gmm owns). v8: with low_mirror_base set, every thin/view descriptor
// for a page in W = [low_mirror_base, +4G) is also written, identically, at its low twin va - low_mirror_base, and
// shot down there too; the space below 4 GiB then belongs to the mirror: every THIN mutator (gmm_vm_range_set[_pages],
// gmm_view_map, gmm_view_unmap's thin path, gmm_view_alias) refuses a range below 4G with GMM_EEXIST (GMM_S1_NONE
// included), and so a range in W whose twin would touch a legacy region, the legacy alias window, or a v3 anchor/view
// (checked on the 16K-rounded range, NONE included). A legacy gmm_reserve below 4G stays legal (KUSER's LOW4G page).
// The reverse: gmm_reserve/gmm_map_view (any flags) are GMM_EEXIST over a low twin in use, and over any part of W
// itself (W holds thin/view memory only). A v3 anchor inside W is NOT refused (anchors write no stage-1 leaves), but
// W is for 32-bit memory only (spec W1): never put an anchor there.
// THE KUSER TWIN HOLE: with Wine's KUSER (a 64K GMM_RESERVE_LOW4G region at 0x7ffe0000), every thin call whose
// 16K-rounded range touches [BASE+0x7ffe0000, BASE+0x7fff0000) is GMM_EEXIST -- GMM_S1_NONE too, so revokes and
// reservation syncs as well. It depends on order: a whole-W NONE succeeds before KUSER is reserved and fails after
// (mirror set at gmm_init; with v9's gmm_set_low_mirror the dividing point is the set instead, see below).
// Wine's vcpu_revoke_pages abort()s on a NONE failure, so Wine's 32-bit allocator must keep guest [0x7ffe0000,
// 0x7fff0000) a permanent hole (large-address-aware and top-down allocations included). A missed widening (a thin
// call with a VA below 4G, NONE included) is GMM_EEXIST too, and would abort the same way.
// PT pool: a fully populated W costs about 8 MiB of leaf tables per side (4 GiB / 4 KiB x 8 bytes), about 16 MiB in
// all for the 32-bit space (the mirror adds half of it), against Wine's 64 MiB VCPU_PT_POOL_SIZE.
// README "v8: the low mirror (WoW64)".

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
// v6: also the invariant the uniform-NONE early-out relies on (gmm.c, thin_apply_locked): outside legacy regions, the
// alias window and registered views, every non-zero stage-1 leaf lies in a 16K chunk some run record covers (skipped
// once a legacy region has been released: gmm_release leaves GMM_TAG_DECOMMITTED leaves behind). A low twin (v8) is
// exempt from it when its canonical page is a run record's or a view's.
// v8: with low_mirror_base set, the mirror invariant: for every 4K page of W, the low twin's leaf and the canonical
// leaf are both invalid or the same valid descriptor (a missing leaf table reads as invalid); a low page inside a
// legacy region is not a twin, and its W page must be invalid. Checked always (not skipped after gmm_release).
int gmm_debug_check(gmm_t *gmm);
// TEST SUPPORT (v6): what the thin mutator did since gmm_init. none_early_outs: uniform GMM_S1_NONE calls that returned
// at once because no run record touches their (16K-rounded) range; none_clips: uniform NONE calls whose range was cut
// down to the run records it touches; pages_applied: 4K pages the thin mutator's per-page loops covered, after any clip.
typedef struct {
  uint64_t none_early_outs, none_clips, pages_applied;
} gmm_debug_thin_t;
void gmm_debug_thin_counts(gmm_t *gmm, gmm_debug_thin_t *out);
// Identity backing: returns (void *)va if the 4K page at va is committed through the thin API, else NULL.
// (gmm_host_ptr() answers the same for thin pages, so existing callers work on either kind of memory.)
void *gmm_vm_host_ptr(gmm_t *gmm, uint64_t va);
// v8: the canonical VA of `va`: with the low mirror on, a VA below 4 GiB that no legacy region covers is the low twin
// of va + low_mirror_base; anything else is returned unchanged. Wine widens a vCPU FAR with it (spec W5).
// NOTE gmm_vm_canon(0) == low_mirror_base (0 is a VA below 4G like any other). Wine's W6 (canonicalising direct
// Nt*VirtualMemory/section/flush address arguments below 4G) must leave 0 alone (it means "anywhere") and otherwise
// use gmm_vm_canon, NOT +BASE: gmm_vm_canon keeps KUSER's legacy low page at 0x7ffe0000 where it is, while +BASE
// would send a 32-bit query of KUSER to BASE+0x7ffe0000, an empty page (the KUSER twin hole above).
// ONLY these accept either form (they canonicalise): gmm_vm_host_ptr, gmm_host_ptr (its thin branch), gmm_vm_s2_mapped
// and gmm_vm_chunk_ipa. Canonical-only: gmm_vm_s2_run, gmm_sect_view_at (0 for a twin), the legacy gmm_query and
// gmm_fault (they do not dealias twins), the legacy branch of gmm_host_ptr (a VA inside a legacy region is its own
// canonical VA), and every mutator. gmm_vm_fault walks the twin as given, with the same verdict as at the canonical VA
// (the twin's leaf equals the canonical one), but Wine canonicalises before it anyway, for virtual_handle_fault's sake.
uint64_t gmm_vm_canon(gmm_t *gmm, uint64_t va);
// v9 (vel1-gmm-v9, appended): turn the low mirror on AFTER gmm_init. The result is exactly the state gmm_init with
// cfg.low_mirror_base = base would have produced, given what the gmm_t holds now. Why: Wine calls gmm_init inside
// virtual_init, before it knows the process is WoW64 and before its allocator exists; a fixed 4 GiB reservation for W
// is unreliable, while a 4 GiB-aligned allocator reservation works (it returned 0x3_0000_0000; Wine's measurement,
// proton-darwin b5d7b96d). So BASE is known only after gmm_init.
// Contract: call it once, after reserving W and before any thin/view use of W or of a VA below 4 GiB. Other gmm calls
// may run concurrently on other threads: it takes the gmm mutex, and every reader of low_mirror_base holds that mutex
// (gmm.c, at gmm_set_low_mirror). It writes no descriptor, issues no TLBI and makes no backend call: the refusals
// below leave nothing in W or below 4 GiB that would need a twin.
// Wine's order, in EVERY vCPU process, WoW64 or not (proton-darwin relay 2026-09-25; gmm_test.c N26d replays it):
// (1) gmm_init(low_mirror_base = 0), KUSER's 64K GMM_RESERVE_LOW4G region reserved at 0x7ffe0000; (2) W reserved
// through Wine's allocator (NtAllocateVirtualMemoryEx, 4 GiB alignment): no gmm call with PMW_VCPU_SKIP_NONE_SYNC
// (Wine's default), else ONE gmm_vm_range_set(W, 4G, GMM_S1_NONE), which with the mirror still off succeeds and
// records nothing (v6's uniform-NONE early-out) -- it must come BEFORE step 3: after it, a whole-W NONE touches the
// KUSER twin hole and is GMM_EEXIST; (3) gmm_set_low_mirror(g, W): 0 in both variants, KUSER present; (4) only then
// the TEB block, TEB32/PEB32 or any 32-bit view in W. A 64-bit process leaves the mirror set (there is no unset call).
//   GMM_EINVAL (checked first): gmm NULL, or `base` fails gmm_init's v8 validation of cfg.low_mirror_base (the same
//     function): 0, not 4 GiB-aligned, base > host VA max - 4G, base + 4G > 2^(64 - t0sz), or [base, +4G) touching
//     [alias_base, +4G) when alias_base != 0.
//   GMM_EEXIST, nothing changed: the mirror is already on (from gmm_init or an earlier call; the same base too), or the
//     contents break a v8 invariant: a thin chunk (any stage-2 mapped identity chunk: committed, NOACCESS or retained)
//     or a registered view or anchor touching W; a thin chunk or a registered view below 4 GiB; a legacy region
//     (gmm_reserve or gmm_map_view, any flags) touching W. A legacy region below 4 GiB (KUSER's LOW4G page at
//     0x7ffe0000) is allowed, as with the mirror set at init (the KUSER twin hole then applies to later thin calls). A
//     thin reservation left at GMM_S1_NONE holds no chunk and is no obstacle, step (2)'s whole-W NONE included. An
//     anchor touching W is refused here, although with the mirror set at init gmm_sect_create would accept one (W is
//     for 32-bit memory only; spec W1).
int gmm_set_low_mirror(gmm_t *gmm, uint64_t base);

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
// v3 SECTIONS (B', vel1-gmm-v3, 2026-09-24): in-process aliasing of a section's views. Design: openrosetta
// docs/superpowers/specs/2026-09-24-gmm-v3-section-alias-design.md. The legacy gmm_section_t/gmm_section_create/
// gmm_map_view are a different, gmm-owned, eager API and are unchanged; nothing below uses them.
//
// A section has ONE host anchor the caller allocated. Each 16K anchor chunk is stage-2 mapped (one IPA, one 16K
// s2_map) the first time any page of it is committed through ANY view, and stays mapped until gmm_sect_destroy.
// Every view -- the first one included -- is stage-1 descriptors only, at the view's own VA, pointing at the anchor
// chunk's IPA; each view has its own commit, protection, guard and NOACCESS state. The view's host side is the
// caller's mach_vm_remap(copy=FALSE) of the anchor at the view VA: gmm validates it and never stage-2 maps it.
// In a process that never creates a section every existing call behaves exactly as in v2.
//
// Existing calls, with sections present:
//   gmm_vm_range_set[_pages] on a range wholly inside one registered view: the VIEW PATH (descriptors at the view's
//     VAs -> anchor IPAs; a page's first commit through any view stage-2 maps its anchor chunk; nothing is ever
//     stage-2 unmapped here). GMM_ENOIPA / GMM_ENOPT surface HERE, at the call that commits the first page of an
//     anchor chunk -- map them to STATUS_NO_MEMORY like any commit. Touching an anchor, or straddling a view's owned
//     range: GMM_EEXIST.
//   gmm_view_unmap(va, size) of exactly a registered view's (va, size): every page RESERVED, one TLBI of the pages
//     that were valid, the view unregistered; no stage-2 operation. Any other range touching a view: GMM_EINVAL.
//   gmm_view_map (identity) touching a view or an anchor: GMM_EEXIST.
//   gmm_vm_s2_mapped: 0 on a view VA, always; on an anchor page, 1 while its chunk is mapped (first commit through a
//     view .. gmm_sect_destroy). gmm_vm_host_ptr/gmm_host_ptr: (void *)va on a view page whose descriptor is
//     committed (valid, or NOACCESS), NULL on an anchor. gmm_vm_fault, gmm_walk, gmm_vm_s2_stats: unchanged.
//
// Caller rules (gmm README "Wine M1 fixes", R8-R12): the anchor is never mprotected, munmapped, madvised or
// MAP_FIXED until gmm_sect_destroy returned 0 (R8); a view's host side is only ever the remap, made BEFORE
// gmm_view_alias, never mprotected (it stays RW) and never executable, replaced only after gmm_view_unmap returned
// (R9; the kernel does NOT refuse PROT_READ|PROT_EXEC on tagged memory); unmap order R10; exact views R11. With
// GMM_CFG_PARANOID, identity (tag-250) memory aliased onto itself is refused too (GMM_EGUARD): its physical page, keyed
// by the full 64-bit VM object id, already stage-2 mapped at another VA.
typedef struct gmm_sect gmm_sect_t;

// The mmap fd-argument for an anchor, VM_MAKE_TAG(252) (the value stays private to gmm.c, as the identity tag does).
// Allocate an anchor as
//   a = mmap(hint, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, gmm_sect_anchor_tag_flag(), 0);
//   minherit(a, size, VM_INHERIT_NONE);
// at a host address that is never a guest VA. VM_INHERIT_NONE is REQUIRED: a fork() with an inheritable anchor puts
// its VM object into copy-on-write while the child lives (measured: share mode SM_COW, a shadow object after the
// next write), and gmm refuses to stage-2 map such memory. NEVER MAP_JIT: that is a caller rule the kernel cannot be
// asked about -- without the hardened runtime an RW MAP_JIT mapping with this tag reads exactly like an anchor (tag,
// protection, max protection, share mode, pager: measured), so no gmm check can refuse it.
int gmm_sect_anchor_tag_flag(void);

// A section anchor that SHARES its bytes with every other process mapping the same object (G14, 2026-09-25; relay
// openrosetta docs/relays/fex-side-shared-sections-2026-09-25.md). `fd` is a POSIX shm object (shm_open, sized once
// with ftruncate: macOS refuses a second ftruncate) of at least `size` bytes; size is a 16K multiple. The anchor is
// mmap(MAP_SHARED, fd) -> mach_make_memory_entry_64 -> mach_vm_map(tag 252, cur=max=READ|WRITE, VM_INHERIT_NONE) at a
// kernel-chosen 16K-aligned address; the temporary mapping is munmapped before return. On 0, *anchor is ready for
// gmm_sect_create exactly like a private anchor (rules R8-R12 apply unchanged: never mprotect/munmap/madvise it until
// gmm_sect_destroy returned 0), and the caller munmap(*anchor, size)s it after gmm_sect_destroy. Returns
//   GMM_EINVAL: anchor NULL, fd < 0, size 0 or not a 16K multiple, fstat fails, or the object is smaller than size;
//   GMM_EGUARD: the object is file-backed (external_pager != 0: Wine's unlinked temp file), is a submap, or cannot be
//     mapped READ|WRITE (an O_RDONLY fd: mmap EPERM/EACCES, or max protection without READ|WRITE) -- a new kind of
//     memory in a VM is how this Mac was panicked, so only anonymous objects pass;
//   GMM_ENOMEM: any other mmap/Mach call failed.
// On every non-zero return nothing is left mapped and *anchor is untouched. The object stays alive while any process
// maps it or holds its fd; each process's gmm_sect_destroy unmaps only its own VM's stage 2.
int gmm_sect_anchor_from_fd(int fd, size_t size, void **anchor);

// Register a section anchor the CALLER allocated (above). anchor and size are 16K multiples; nothing is stage-2
// mapped and no IPA is consumed (an anchor costs host VA only, so a section may be larger than the IPA window).
// Checks: alignment (GMM_EINVAL); [anchor, anchor+size) overlaps no other anchor, no view's owned range, no stage-2
// mapped identity chunk, no legacy region and not the alias window (GMM_EEXIST); the host entries at the first and
// the last chunk are tag 252, current protection exactly READ|WRITE, not file-backed, not a submap, VM_INHERIT_NONE
// (GMM_EGUARD; with GMM_CFG_PARANOID every entry is walked). The per-chunk anchor guard before every stage-2 map is
// the authoritative check. Returns 0, GMM_EINVAL, GMM_EEXIST, GMM_EGUARD or GMM_ENOMEM.
int gmm_sect_create(gmm_t *gmm, void *anchor, size_t size, gmm_sect_t **out);

// Unregister a section with no views: one exact 16K stage-2 unmap per mapped anchor chunk, then its IPA is freed.
// No TLBI: every descriptor that referenced those IPAs was invalidated and shot down when its view was unmapped.
// GMM_EBUSY (nothing changed) while any view is registered; GMM_EINVAL if sect is not a live section of gmm (a stale
// pointer whose address a NEW section has since reused cannot be told apart: it names the new section). After
// a 0 return gmm_vm_s2_mapped() is 0 on the whole anchor and the caller may munmap it. With GMM_CFG_PARANOID every
// mapped chunk is re-checked first and gmm aborts on a changed anchor (a broken R8).
int gmm_sect_destroy(gmm_t *gmm, gmm_sect_t *sect);

// Map a view: [va, va+size) aliases section bytes [off, off+size), and the view owns [va, round16K(va+size)).
//   va % 16K == 0, off % 16K == 0, size % 4K == 0, off + size <= the section's size; else GMM_EINVAL (the view is
//   not host-congruent: keep the caller's copy path).
//   The caller has ALREADY made [va, round16K(va+size)) a mach_vm_remap(copy=FALSE, ..., VM_INHERIT_NONE) of
//   anchor+off. gmm checks it at every host entry: tag 252, protection exactly READ|WRITE, VM_INHERIT_NONE, not a
//   submap, not file-backed, truly shared (SM_TRUESHARED, with the anchor's page_info depth) and the same VM object
//   (its full 64-bit id) and object offset as the anchor at that offset; else GMM_EGUARD, nothing registered. A
//   copy=TRUE (copy-on-write) remap is refused by the SM_TRUESHARED/depth check: it is never truly shared with the
//   anchor.
//   The owned range overlapping a registered view, an anchor, a stage-2 mapped identity chunk, a legacy region or
//   the alias window: GMM_EEXIST.
//   Then the view is registered and s1 is applied to every page as gmm_vm_range_set would (usually GMM_S1_NONE).
// Returns 0, GMM_EINVAL, GMM_EEXIST, GMM_EGUARD, GMM_ENOMEM, and -- only when s1 != GMM_S1_NONE -- the commit
// errors GMM_ENOIPA, GMM_ENOPT, GMM_ES2 (then nothing is registered either).
int gmm_view_alias(gmm_t *gmm, gmm_sect_t *sect, uint64_t off, uint64_t va, size_t size, unsigned s1);

// TEST/CALLER SUPPORT: 1 and the view whose [va, va+size) holds va (its section, base, size, and the section offset
// of va's 4K page), else 0. Any output pointer may be NULL.
int gmm_sect_view_at(gmm_t *gmm, uint64_t va, gmm_sect_t **sect, uint64_t *view_va, uint64_t *view_size,
                     uint64_t *off);

// TEST SUPPORT. All zero if sect is not a live section of gmm (a stale pointer reused by a new section reads that one).
typedef struct {
  void *anchor;
  uint64_t size;
  uint64_t views;          // registered views
  uint64_t mapped_chunks;  // anchor chunks stage-2 mapped (each 16K, each its own s2_map)
  uint64_t s2_maps, s2_unmaps;
} gmm_sect_info_t;
void gmm_sect_info(gmm_t *gmm, gmm_sect_t *sect, gmm_sect_info_t *out);

// TEST SUPPORT: stage-2 map every not-yet-mapped anchor chunk overlapping section bytes [off, off+size), exactly as
// a first commit through a view would (anchor guard, one IPA and one 16K s2_map each, all or nothing); no descriptor
// is written. Returns 0, GMM_EINVAL, GMM_ENOIPA, GMM_EGUARD, GMM_ENOMEM or GMM_ES2.
int gmm_debug_sect_map(gmm_t *gmm, gmm_sect_t *sect, uint64_t off, size_t size);
// TEST SUPPORT: the same, but keyed and mapped at host base + offset for a CALLER-CHOSEN base, and with no check that
// [off, off+size) lies inside the section. Every real caller passes the registered anchor; this door exists so a test
// can show that the section map path refuses anything else -- a view's remap, a VA inside the anchor that is not its
// base, a chunk at or past the section's end -- with GMM_EGUARD before anything is mapped. Never call it otherwise.
int gmm_debug_sect_map_at(gmm_t *gmm, gmm_sect_t *sect, uint64_t base, uint64_t off, size_t size);

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
// TEST SUPPORT (not in the design's §1 API list): an internal event trace, used by N4's revocation-order checker, by
// gmm_vm.c's stage-2 checks and available to any other test. v6: recorded only with cfg.flags & GMM_CFG_TRACE (off by
// default; gmm_trace_count() then stays 0). Recording costs one dynamic-array append per event and the array is never
// shrunk -- test support only, never for a production caller (Wine must not set GMM_CFG_TRACE).
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

#ifdef GMM_PROFILE
// TEST SUPPORT, compiled in only with -DGMM_PROFILE (gmm_bench.c; never the harness or the test suite): wall time
// per phase of the thin mutator (thin_apply_locked), accumulated process-wide since the last reset. Each phase
// boundary is one clock read (CLOCK_UPTIME_RAW, 24 MHz on Apple silicon, so single laps are quantised to ~42 ns;
// only sums over many calls mean anything). GMM_PROF_TRACE is nested inside the other phases (mostly DESC): it is
// reported on its own and is ALSO included in its enclosing phase.
typedef enum {
  GMM_PROF_ARGS,       // lock taken -> arguments validated, legacy-region/alias overlap checked
  GMM_PROF_PLAN,       // per-chunk plan (chunk-hash lookups, masks) + ipa_available
  GMM_PROF_PT,         // stage-1 table allocation (pt_ensure)
  GMM_PROF_GUARD,      // runs: caller_region_end (the host-region query, once per run)
  GMM_PROF_IPA,        // contiguous IPA allocation per run
  GMM_PROF_URECS,      // which run records lose chunks (+ the remap policy's survivor scan)
  GMM_PROF_RESERVE,    // scratch buffers, chunk-hash and record reservation
  GMM_PROF_S2MAP,      // backend->s2_map calls
  GMM_PROF_INSERT,     // chunk-hash inserts + run-record inserts
  GMM_PROF_DESC,       // descriptor writes (+ committed masks, + the remap policy's survivor invalidation)
  GMM_PROF_TLBI,       // the batched shootdown
  GMM_PROF_UNMAP,      // stage-2 unmaps, record removal/split, IPA free
  GMM_PROF_FREE,       // scratch frees
  GMM_PROF_TRACE,      // trace_push (nested: see above); always 0 without GMM_CFG_TRACE (v6)
  GMM_PROF_N
} gmm_prof_phase_t;
void gmm_debug_prof_get(uint64_t ns[GMM_PROF_N]);  // copies the sums
void gmm_debug_prof_reset(void);
#endif

#ifdef __cplusplus
}
#endif
