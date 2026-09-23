// SPDX-License-Identifier: MIT
//
// gmm.c — the guest memory manager core. No hv_*/Hypervisor.framework anywhere in this file (§0/ABSOLUTE SAFETY
// RULE in the task brief: gmm_vm.c's live path, if/when it exists, is a SEPARATE file that owns the actual
// hv_vm_map/hv_vm_unmap calls behind the gmm_backend_t it hands to gmm_init()). This file only ever calls
// mmap/munmap/mach_vm_region on memory it allocated itself (the "backing guard", §2), which is native and safe.
//
// One mutex serializes every mutating call (§2, "One mutex"). Descriptor writes use a single atomic-release
// 64-bit store so a lock-free reader (N8's emulated vCPUs, or eventually real hardware) never observes a torn
// write, even though gmm's own mutators are already serialized against each other by the mutex.
#include "gmm.h"

#include <stdio.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_purgable.h>
#include <mach/vm_region.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

// ================================================================================================================
// Backing guard (§2). VM_MAKE_TAG'd anonymous memory only; checked with mach_vm_region right before every
// backend->s2_map(), exactly as required. This is the one place gmm.c talks to the kernel about memory *shape*
// (never about virtualization — nothing here is hv_*).
#define GMM_VM_TAG 250  // an application-specific tag in Apple's reserved 240-255 range

// VM_MAKE_TAG(tag) expands to plain "(tag) << 24"; with GMM_VM_TAG as a bare int literal that shift overflows
// int (250 << 24 > INT_MAX), which is undefined behaviour per C11 6.5.7p4 — UBSan caught this during N3. Casting
// to unsigned first makes the shift well-defined (wraps into the sign bit, which is exactly the bit pattern the
// mmap fd-argument ABI expects here).
static int gmm_tag_flag(void) { return VM_MAKE_TAG((unsigned)GMM_VM_TAG); }

static void *gmm_host_alloc(size_t sz) {
  void *p = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, gmm_tag_flag(), 0);
  return (p == MAP_FAILED) ? NULL : p;
}
static void gmm_host_free(void *p, size_t sz) {
  if (p) munmap(p, sz);
}
// Returns 0 if [host, host+sz) is entirely our own VM_MAKE_TAG'd, non-executable anonymous memory; -1 otherwise.
// Callers abort() on -1 (§2: "before every s2_map, mach_vm_region must show the GMM tag and no VM_PROT_EXECUTE,
// else abort" — extends hvf_fex_vk.cpp:367-374's executable-anonymous-memory guard with the tag check).
static int gmm_backing_check(void *host, size_t sz) {
  mach_vm_address_t addr = (mach_vm_address_t)(uintptr_t)host;
  mach_vm_size_t regsz = 0;
  vm_region_extended_info_data_t info;
  mach_msg_type_number_t count = VM_REGION_EXTENDED_INFO_COUNT;
  mach_port_t obj = MACH_PORT_NULL;
  kern_return_t kr =
      mach_vm_region(mach_task_self(), &addr, &regsz, VM_REGION_EXTENDED_INFO, (vm_region_info_t)&info, &count, &obj);
  if (obj != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), obj);
  if (kr != KERN_SUCCESS) return -1;
  if (addr > (mach_vm_address_t)(uintptr_t)host) return -1;         // nothing mapped at host: a gap
  if (addr + regsz < (mach_vm_address_t)(uintptr_t)host + sz) return -1; // region doesn't cover the whole chunk
  if (info.user_tag != GMM_VM_TAG) return -1;
  if (info.protection & VM_PROT_EXECUTE) return -1;
  return 0;
}

// Wine M1 identity backing: the guard for memory the CALLER owns (thin API). Everything gmm_backing_check()
// demands, plus what gmm could previously take for granted because it made the mapping itself: the chunk is
// covered by ONE region (no hole, no second region with other attributes), its current protection is exactly
// READ|WRITE (a PROT_NONE or read-only page handed to hv_vm_map is an unexplored class; EXECUTE is the MAP_JIT
// panic class), and it is not file-backed (external_pager == 0; a file mapping cannot carry the tag anyway, since
// the tag rides mmap's fd argument, but this does not rely on that). The region may be larger than the chunk (a
// Wine view is one mmap). max_protection is NOT checked: mmap gives VM_PROT_ALL there, and the kernel already
// refuses to add EXECUTE to a tag-250 mapping later (gmm/README.md "Design issues" 4).
static int gmm_backing_check_caller(uint64_t va, size_t sz) {
  mach_vm_address_t addr = (mach_vm_address_t)va;
  mach_vm_size_t regsz = 0;
  vm_region_extended_info_data_t ext;
  mach_msg_type_number_t count = VM_REGION_EXTENDED_INFO_COUNT;
  mach_port_t obj = MACH_PORT_NULL;
  kern_return_t kr =
      mach_vm_region(mach_task_self(), &addr, &regsz, VM_REGION_EXTENDED_INFO, (vm_region_info_t)&ext, &count, &obj);
  if (obj != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), obj);
  if (kr != KERN_SUCCESS) return -1;
  if (addr > va || addr + regsz < va + sz) return -1;  // a gap, or the chunk spans two regions
  if (ext.user_tag != GMM_VM_TAG) return -1;
  if (ext.external_pager != 0) return -1;
  if ((ext.protection & (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE)) != (VM_PROT_READ | VM_PROT_WRITE)) return -1;
  return 0;
}

// ================================================================================================================
// G7/N11: foreign memory (gmm.h's "G7/N11" section has the full contract). Still no hv_*/Hypervisor.framework --
// gmm_foreign_map/gmm_foreign_backing_check only ever call mach_vm_map/mach_vm_region/mach_vm_purgable_control on
// memory a foreign process owns, which is exactly the same class of "talk to the kernel about memory *shape*"
// this file already does for its own backing guard above, just of a named-entry-derived mapping instead of one
// gmm allocated itself.
#define GMM_FOREIGN_VM_TAG 251  // deliberately distinct from GMM_VM_TAG (250): must NEVER satisfy gmm_backing_check
// SM_TRUESHARED (5): measured in-process 5/5 runs while building N11a (a wineserver-shaped owner page -- anon,
// tag 0, VM_INHERIT_SHARE -- named via mach_make_memory_entry_64(VM_PROT_DEFAULT), mapped here VM_INHERIT_NONE).
// A file-backed entry measures share_mode=4 (SM_SHARED) with external_pager=1 -- both already refused by the
// separate external_pager check, so share_mode alone would also catch it. See gmm/README.md's "N11" section for
// the full measured table (ref_count across the handoff, the 32K-region and file-backed numbers, and the
// purgable-control KERN_INVALID_ARGUMENT result on this class of memory). If a future run ever sees this value
// move, that is exactly the kind of contradiction the design doc asks N11 to surface -- do not silently widen
// this to "accept whatever we saw"; report it.
#define GMM_FOREIGN_EXPECTED_SHARE_MODE 5

#define GMM_FOREIGN_REG_MAX 64
typedef struct {
  void *host;
  size_t sz;
} gmm_foreign_reg_entry_t;
static gmm_foreign_reg_entry_t g_foreign_reg[GMM_FOREIGN_REG_MAX];
static size_t g_foreign_reg_n = 0;
static pthread_mutex_t g_foreign_reg_mtx = PTHREAD_MUTEX_INITIALIZER;

static int gmm_foreign_tag_flag(void) { return VM_MAKE_TAG((unsigned)GMM_FOREIGN_VM_TAG); }
int gmm_debug_foreign_tag_flag(void) { return gmm_foreign_tag_flag(); }

static void foreign_reg_add(void *host, size_t sz) {
  pthread_mutex_lock(&g_foreign_reg_mtx);
  if (g_foreign_reg_n < GMM_FOREIGN_REG_MAX) g_foreign_reg[g_foreign_reg_n++] = (gmm_foreign_reg_entry_t){host, sz};
  // else: registry full -- the mapping still succeeded (gmm_foreign_map's return value says so), it just will
  // never pass gmm_foreign_backing_check()'s registry check. N11's tests never come close to 64 live mappings.
  pthread_mutex_unlock(&g_foreign_reg_mtx);
}
static int foreign_reg_has(void *host, size_t sz) {
  int found = 0;
  pthread_mutex_lock(&g_foreign_reg_mtx);
  for (size_t i = 0; i < g_foreign_reg_n; i++) {
    if (g_foreign_reg[i].host == host && g_foreign_reg[i].sz == sz) {
      found = 1;
      break;
    }
  }
  pthread_mutex_unlock(&g_foreign_reg_mtx);
  return found;
}

int gmm_foreign_map(gmm_t *gmm, mach_port_t entry, size_t sz, void **out) {
  (void)gmm;  // accepted for API symmetry only (gmm.h's "G7/N11" note) -- the registry is process-global, not
              // gmm_t-scoped, so nothing here reads or writes *gmm.
  if (entry == MACH_PORT_NULL || sz == 0 || !out) return -1;
  mach_vm_address_t addr = 0;
  kern_return_t kr = mach_vm_map(mach_task_self(), &addr, (mach_vm_size_t)sz, 0,
                                  VM_FLAGS_ANYWHERE | gmm_foreign_tag_flag(), entry, 0, /*copy=*/FALSE,
                                  VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_NONE);
  if (kr != KERN_SUCCESS) return -1;
  *out = (void *)(uintptr_t)addr;
  foreign_reg_add(*out, sz);
  return 0;
}

int gmm_foreign_backing_check(void *p, size_t sz) {
  if (!p || sz != 16384) return -1;

  // VM_REGION_BASIC_INFO_64: protection / max_protection (the EXECUTE check the task brief calls out by name).
  {
    mach_vm_address_t addr = (mach_vm_address_t)(uintptr_t)p;
    mach_vm_size_t regsz = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;
    kern_return_t kr =
        mach_vm_region(mach_task_self(), &addr, &regsz, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &obj);
    if (obj != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), obj);
    if (kr != KERN_SUCCESS) return -1;
    if (addr != (mach_vm_address_t)(uintptr_t)p) return -1;  // must start exactly at p, not merely cover it
    if (regsz != sz) return -1;                              // must be EXACTLY 16K, not a sub-range of something bigger
    if (info.protection & VM_PROT_EXECUTE) return -1;
    if (info.max_protection & VM_PROT_EXECUTE) return -1;
  }

  // VM_REGION_EXTENDED_INFO: user_tag / external_pager / share_mode.
  {
    mach_vm_address_t addr = (mach_vm_address_t)(uintptr_t)p;
    mach_vm_size_t regsz = 0;
    vm_region_extended_info_data_t info;
    mach_msg_type_number_t count = VM_REGION_EXTENDED_INFO_COUNT;
    mach_port_t obj = MACH_PORT_NULL;
    kern_return_t kr = mach_vm_region(mach_task_self(), &addr, &regsz, VM_REGION_EXTENDED_INFO, (vm_region_info_t)&info,
                                       &count, &obj);
    if (obj != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), obj);
    if (kr != KERN_SUCCESS) return -1;
    if (addr != (mach_vm_address_t)(uintptr_t)p || regsz != sz) return -1;
    if (info.user_tag != GMM_FOREIGN_VM_TAG) return -1;
    if (info.external_pager != 0) return -1;
    if (info.share_mode != GMM_FOREIGN_EXPECTED_SHARE_MODE) return -1;
  }

  // Purgeable-volatile: refuse VOLATILE/EMPTY. A control failure (KERN_INVALID_ARGUMENT, measured for this class
  // of memory -- see the GMM_FOREIGN_EXPECTED_SHARE_MODE comment above) means "not purgeable-controllable at
  // all", which is a pass, not a rejection: msync-shaped pages are never made purgeable.
  {
    int state = 0;
    kern_return_t kr = mach_vm_purgable_control(mach_task_self(), (mach_vm_address_t)(uintptr_t)p, VM_PURGABLE_GET_STATE, &state);
    if (kr == KERN_SUCCESS) {
      int s = state & VM_PURGABLE_STATE_MASK;
      if (s == VM_PURGABLE_VOLATILE || s == VM_PURGABLE_EMPTY) return -1;
    }
  }

  if (!foreign_reg_has(p, sz)) return -1;
  return 0;
}

// gmm_foreign_s2_map is defined further down (needs the full `struct gmm` definition, below) -- see there.

// ================================================================================================================
// vprot: one uint16_t per 4K page (§2). bit0 = committed; bits[12:1] = full GMM_PAGE_* (base|modifiers, 0..0xFFF);
// bit13 = write-watch overlay; bit14 = SMC overlay. bit15 unused.
#define VP_COMMITTED_BIT (1u << 0)
#define VP_PROT_SHIFT 1
#define VP_PROT_MASK (0xFFFu << VP_PROT_SHIFT)
#define VP_WW_BIT (1u << 13)
#define VP_SMC_BIT (1u << 14)

static inline int vp_committed(uint16_t vp) { return (vp & VP_COMMITTED_BIT) != 0; }
static inline unsigned vp_prot(uint16_t vp) { return (vp & VP_PROT_MASK) >> VP_PROT_SHIFT; }
static inline unsigned vp_overlay(uint16_t vp) {
  unsigned o = 0;
  if (vp & VP_WW_BIT) o |= GMM_OVERLAY_WRITEWATCH;
  if (vp & VP_SMC_BIT) o |= GMM_OVERLAY_SMC;
  return o;
}
static inline uint16_t vp_make(int committed, unsigned prot, unsigned overlay) {
  uint16_t v = 0;
  if (committed) v |= VP_COMMITTED_BIT;
  v |= (uint16_t)((prot & 0xFFFu) << VP_PROT_SHIFT);
  if (overlay & GMM_OVERLAY_WRITEWATCH) v |= VP_WW_BIT;
  if (overlay & GMM_OVERLAY_SMC) v |= VP_SMC_BIT;
  return v;
}

// ================================================================================================================
// Chunk table (§2): one entry per 16K host-backed chunk, owned inline by whichever region/section covers it —
// never freed/moved independently, so "region base + chunk index" is a stable, O(1) key. host==NULL means the
// chunk has never been touched (no backing allocated yet; PRIVATE regions only — section chunks are all backed
// eagerly at creation).
#define GMM_IPA_NONE UINT64_MAX
typedef struct {
  void *host;
  uint64_t ipa;
  uint8_t s2_mapped;
  uint8_t refs;  // 0..4: number of currently-COMMITTED 4K subpages (commit/decommit only; protect never touches it)
} gmm_chunk_t;

struct gmm_section {
  size_t size;      // rounded up to 16K
  size_t nchunks;
  void **host;       // nchunks entries, each a 16K gmm_host_alloc()
  uint64_t *ipa;       // nchunks entries, each s2_mapped R|W|X at gmm_section_create() time
};

typedef struct {
  uint64_t base, size;  // VA range
  uint32_t alloc_prot;   // AllocationProtect (informational, as given at reserve/map_view time)
  uint32_t type;          // GMM_TYPE_PRIVATE / GMM_TYPE_MAPPED
  int low4g;
  gmm_section_t *section;  // MAPPED only
  uint64_t view_off;        // MAPPED only: offset into section
  uint16_t *vprot;            // size/4096 entries
  gmm_chunk_t *chunks;          // size/16384 entries; NULL for MAPPED (section owns the backing)
} gmm_region_t;

// Wine M1 thin API: one entry per 16K host page that is currently stage-2 mapped (identity backing: the host page
// IS the guest page, so the key is its VA). Present <=> stage-2 mapped <=> at least one of its four 4K pages is
// committed (outside a gmm call). Open-addressing hash, linear probing, backward-shift deletion (no tombstones).
typedef struct {
  uint64_t key;       // chunk VA | 1 (never 0, so 0 marks an empty slot)
  uint64_t ipa;
  uint8_t committed;  // bit i = 4K page i of the chunk is committed
} tchunk_t;
typedef struct {
  tchunk_t *slots;
  size_t cap, n;  // cap: power of two (or 0); load kept <= 1/2
} tchunk_tab_t;

// Dynamic vector of freed IPAs (§2 IPA allocator: "bump + free list").
typedef struct {
  uint64_t *items;
  size_t n, cap;
} u64_vec_t;
__attribute__((unused)) static void vec_push(u64_vec_t *v, uint64_t x) {
  if (v->n == v->cap) {
    v->cap = v->cap ? v->cap * 2 : 16;
    v->items = realloc(v->items, v->cap * sizeof(uint64_t));
  }
  v->items[v->n++] = x;
}
__attribute__((unused)) static int vec_pop(u64_vec_t *v, uint64_t *out) {
  if (!v->n) return 0;
  *out = v->items[--v->n];
  return 1;
}
typedef struct {
  uint64_t lo, hi;  // [lo, hi), 16K aligned
} ipa_ext_t;
// FAST MAPPING: one live stage-2 mapping of the thin API (gmm.h "run record").
typedef struct {
  uint64_t va, ipa, nchunks;
  int whole;  // 1: [ipa, ipa + nchunks*16K) is EXACTLY the range of the one s2_map call that created it (an unmap
              // of the whole record is then an "exact" unmap, the shape proven live since G5a); 0: a piece left by
              // a sub-range unmap (split), so unmapping it is itself a sub-range unmap of the original call
} s2rec_t;

struct gmm {
  gmm_config_t cfg;
  gmm_backend_t backend;
  pthread_mutex_t mtx;

  uint64_t root_ipa;      // TTBR0 value: IPA of the top-level table
  uint64_t pt_pool_used;   // bump allocator into cfg.pt_pool_host/pt_pool_sz; "tables never freed" (§2)

  uint64_t ipa_bump;        // lowest never-handed-out data IPA: [ipa_bump, cfg.ipa_hi) is free
  // Freed IPA ranges, reusable once their revocation's tlbi_sync AND s2_unmap have returned (§2, quarantine: since
  // tlbi_sync() is a SYNCHRONOUS backend call by contract, a range is freed only after that call and the stage-2
  // unmap have returned, so the "quarantine" window is exactly "not on the free list until its shootdown and unmap
  // are provably done"). FAST MAPPING (2026-09-23): was a LIFO stack of single 16K IPAs; now an address-sorted,
  // coalesced list of [lo, hi) extents so a run can get a CONTIGUOUS range. Allocation is first-fit (lowest
  // address), then the untouched top; a freed extent that reaches ipa_bump folds back into it. With one free
  // entry (G5b's recommit, N4) the result equals the old LIFO: the freed IPA comes straight back.
  ipa_ext_t *ifree;
  size_t nifree, capifree;

  gmm_region_t *regions;  // sorted by base, no overlaps
  size_t nregions, cap_regions;

  tchunk_tab_t thin;  // Wine M1 thin API: stage-2-mapped identity chunks (see tchunk_t)
  // FAST MAPPING: the thin API's live stage-2 mappings ("run records"), sorted by va, disjoint, no holes. Every
  // thin chunk lies in exactly one record and its IPA is rec.ipa + (chunk va - rec.va).
  s2rec_t *recs;
  size_t nrecs, caprecs;
  gmm_s2_stats_t st;  // counters (records/mapped/retained are computed on demand by gmm_vm_s2_stats)

  gmm_ev_t *trace;
  size_t ntrace, cap_trace;
};

// ================================================================================================================
// Thin-chunk hash table (Wine M1).
static size_t tchunk_hash(const tchunk_tab_t *t, uint64_t key) {
  return (size_t)(((key >> 14) * 0x9E3779B97F4A7C15ull) >> 20) & (t->cap - 1);
}
static tchunk_t *tchunk_find(tchunk_tab_t *t, uint64_t chunk_va) {
  if (!t->cap) return NULL;
  const uint64_t key = chunk_va | 1;
  for (size_t i = tchunk_hash(t, key);; i = (i + 1) & (t->cap - 1)) {
    if (t->slots[i].key == key) return &t->slots[i];
    if (!t->slots[i].key) return NULL;
  }
}
// Grows the table so `extra` more inserts cannot trigger a rehash. Returns 0, or -1 on allocation failure (the
// table is unchanged). Must run before anything in a call is mutated, since insert itself never fails.
static int tchunk_reserve(tchunk_tab_t *t, size_t extra) {
  if ((t->n + extra) * 2 <= t->cap) return 0;
  size_t ncap = t->cap ? t->cap : 64;
  while ((t->n + extra) * 2 > ncap) ncap *= 2;
  tchunk_t *ns = calloc(ncap, sizeof(tchunk_t));
  if (!ns) return -1;
  tchunk_tab_t nt = {ns, ncap, 0};
  for (size_t i = 0; i < t->cap; i++) {
    if (!t->slots[i].key) continue;
    size_t j = tchunk_hash(&nt, t->slots[i].key);
    while (nt.slots[j].key) j = (j + 1) & (ncap - 1);
    nt.slots[j] = t->slots[i];
    nt.n++;
  }
  free(t->slots);
  *t = nt;
  return 0;
}
static tchunk_t *tchunk_insert(tchunk_tab_t *t, uint64_t chunk_va, uint64_t ipa) {
  const uint64_t key = chunk_va | 1;
  size_t i = tchunk_hash(t, key);
  while (t->slots[i].key) i = (i + 1) & (t->cap - 1);
  t->slots[i] = (tchunk_t){.key = key, .ipa = ipa, .committed = 0};
  t->n++;
  return &t->slots[i];
}
static void tchunk_remove(tchunk_tab_t *t, tchunk_t *e) {
  size_t i = (size_t)(e - t->slots);
  t->slots[i].key = 0;
  t->n--;
  // backward-shift: move later members of the probe run into the hole if their home slot allows it
  for (size_t j = (i + 1) & (t->cap - 1); t->slots[j].key; j = (j + 1) & (t->cap - 1)) {
    const size_t h = tchunk_hash(t, t->slots[j].key);
    const int between = (i <= j) ? (i < h && h <= j) : (i < h || h <= j);
    if (between) continue;  // home slot is after the hole (cyclically): stays put
    t->slots[i] = t->slots[j];
    t->slots[j].key = 0;
    i = j;
  }
}
// 1 if any thin chunk overlapping [va, va+sz) exists (i.e. is stage-2 mapped with committed pages).
static int tchunk_any_in(tchunk_tab_t *t, uint64_t va, uint64_t sz) {
  if (!t->n || !sz) return 0;
  const uint64_t c0 = va & ~16383ull, c1 = (va + sz - 1) & ~16383ull;
  if ((c1 - c0) / 16384 + 1 > t->cap) {  // big range: scan the table instead of probing every chunk
    for (size_t i = 0; i < t->cap; i++) {
      const uint64_t k = t->slots[i].key & ~1ull;
      if (t->slots[i].key && k >= c0 && k <= c1) return 1;
    }
    return 0;
  }
  for (uint64_t c = c0;; c += 16384) {
    if (tchunk_find(t, c)) return 1;
    if (c == c1) break;
  }
  return 0;
}

// ================================================================================================================
// G7/N11: gmm_foreign_s2_map, deferred to here from beside gmm_foreign_map/gmm_foreign_backing_check above
// because it needs the full `struct gmm` (cfg.foreign_ipa_lo/hi, backend.s2_map_foreign), just defined.
int gmm_foreign_s2_map(gmm_t *gmm, void *host, uint64_t ipa, size_t sz, int perm) {
  if (!gmm) return -1;
  if (perm != GMM_S2_R) return -1;  // G7: "Stage-2 READ only" -- never W, never X, and never a combination
  if (gmm->cfg.foreign_ipa_lo == gmm->cfg.foreign_ipa_hi) return -1;  // no foreign window configured
  if (ipa < gmm->cfg.foreign_ipa_lo) return -1;
  if (sz == 0 || ipa + sz < ipa) return -1;  // overflow guard
  if (ipa + sz > gmm->cfg.foreign_ipa_hi) return -1;
  if (gmm_foreign_backing_check(host, sz) != 0) return -1;  // re-checked here: a caller must not be able to skip
                                                              // the guard by calling this wrapper directly
  if (!gmm->backend.s2_map_foreign) return -1;
  uint32_t r = gmm->backend.s2_map_foreign(host, ipa, sz, perm);
  return r == 0 ? 0 : -1;
}

// ================================================================================================================
// Trace (TEST SUPPORT, gmm.h).
static void trace_push_sz(gmm_t *g, gmm_ev_kind_t kind, uint64_t va, uint64_t ipa, uint64_t sz) {
  if (g->ntrace == g->cap_trace) {
    g->cap_trace = g->cap_trace ? g->cap_trace * 2 : 256;
    g->trace = realloc(g->trace, g->cap_trace * sizeof(gmm_ev_t));
  }
  g->trace[g->ntrace++] = (gmm_ev_t){.kind = kind, .va = va, .ipa = ipa, .sz = sz};
}
// Every pre-FAST-MAPPING stage-2 event is one 16K chunk.
static void trace_push(gmm_t *g, gmm_ev_kind_t kind, uint64_t va, uint64_t ipa) {
  trace_push_sz(g, kind, va, ipa, (kind == GMM_EV_S2_MAP || kind == GMM_EV_S2_UNMAP) ? 16384 : 0);
}
size_t gmm_trace_count(gmm_t *g) { return g->ntrace; }
gmm_ev_t gmm_trace_get(gmm_t *g, size_t i) { return g->trace[i]; }
void gmm_trace_clear(gmm_t *g) { g->ntrace = 0; }

// ================================================================================================================
// Region array: sorted, no overlaps, linear scan (region counts stay small — a handful to a few hundred live
// allocations even under the N8 soak, since release/decommit keep it bounded).
static gmm_region_t *find_region(gmm_t *g, uint64_t va) {
  for (size_t i = 0; i < g->nregions; i++) {
    gmm_region_t *r = &g->regions[i];
    if (va >= r->base && va < r->base + r->size) return r;
  }
  return NULL;
}
static gmm_region_t *find_region_exact(gmm_t *g, uint64_t base) {
  for (size_t i = 0; i < g->nregions; i++)
    if (g->regions[i].base == base) return &g->regions[i];
  return NULL;
}
static int regions_overlap(gmm_t *g, uint64_t base, uint64_t size) {
  for (size_t i = 0; i < g->nregions; i++) {
    gmm_region_t *r = &g->regions[i];
    if (base < r->base + r->size && r->base < base + size) return 1;
  }
  return 0;
}
static gmm_region_t *region_insert(gmm_t *g, gmm_region_t rec) {
  if (g->nregions == g->cap_regions) {
    g->cap_regions = g->cap_regions ? g->cap_regions * 2 : 16;
    g->regions = realloc(g->regions, g->cap_regions * sizeof(gmm_region_t));
  }
  size_t i = g->nregions;
  while (i > 0 && g->regions[i - 1].base > rec.base) i--;
  memmove(&g->regions[i + 1], &g->regions[i], (g->nregions - i) * sizeof(gmm_region_t));
  g->regions[i] = rec;
  g->nregions++;
  return &g->regions[i];
}
static void region_remove(gmm_t *g, gmm_region_t *r) {
  size_t i = (size_t)(r - g->regions);
  free(r->vprot);
  free(r->chunks);
  memmove(&g->regions[i], &g->regions[i + 1], (g->nregions - i - 1) * sizeof(gmm_region_t));
  g->nregions--;
}

// ================================================================================================================
// Address rule (§1): dealias a FAR/query address that falls in [alias_base, alias_base+4G) back to its canonical
// <4GiB VA, IF that canonical VA is covered by a low4g region. Used by gmm_fault/gmm_query/gmm_host_ptr/gmm_walk
// so they accept either alias a caller might legitimately present. gmm_reserve/commit/decommit/protect are always
// called with the CANONICAL address by convention (documented in gmm.h); they write both aliases internally.
static uint64_t dealias(gmm_t *g, uint64_t va) {
  if (!g->cfg.alias_base) return va;
  if (va < g->cfg.alias_base || va >= g->cfg.alias_base + 0x100000000ull) return va;
  uint64_t canon = va - g->cfg.alias_base;
  gmm_region_t *r = find_region(g, canon);
  return (r && r->low4g) ? canon : va;
}

// ================================================================================================================
// PT pool suballocator + descriptor tree (§2, GuestMirror pattern: same 4-level-max walk, tables never freed).
static uint64_t pt_alloc_table(gmm_t *g) {
  if (g->pt_pool_used + 4096 > g->cfg.pt_pool_sz) return GMM_IPA_NONE;
  uint64_t ipa = g->cfg.pt_pool_ipa + g->pt_pool_used;
  memset((uint8_t *)g->cfg.pt_pool_host + g->pt_pool_used, 0, 4096);
  g->pt_pool_used += 4096;
  return ipa;
}
static inline uint64_t *pt_table_ptr(gmm_t *g, uint64_t ipa) {
  return (uint64_t *)((uint8_t *)g->cfg.pt_pool_host + (ipa - g->cfg.pt_pool_ipa));
}
// Writes one leaf descriptor for `va`, allocating intermediate tables on demand. Single atomic-release store to
// the final slot (§2: "single aligned 64-bit release stores"). Returns 0 on success, -1 on PT-pool exhaustion.
// Returns the leaf slot for `va`, allocating intermediate tables on demand; NULL on PT-pool exhaustion.
static uint64_t *pt_walk_alloc(gmm_t *g, uint64_t va) {
  uint64_t t = g->root_ipa;
  const int start = gmm_start_level_for_t0sz(g->cfg.t0sz);
  for (int level = start; level < 3; level++) {
    const int shift = 12 + 9 * (3 - level);
    const unsigned idx = (unsigned)((va >> shift) & 0x1FFull);
    uint64_t *slot = &pt_table_ptr(g, t)[idx];
    uint64_t e = *slot;
    if (!(e & 1ull)) {
      uint64_t nt = pt_alloc_table(g);
      if (nt == GMM_IPA_NONE) return NULL;
      e = nt | 0x3ull;
      __atomic_store_n(slot, e, __ATOMIC_RELEASE);
    }
    t = e & 0x0000fffffffff000ull;
  }
  return &pt_table_ptr(g, t)[(va >> 12) & 0x1FFull];
}
static int pt_set_leaf(gmm_t *g, uint64_t va, uint64_t desc) {
  uint64_t *slot = pt_walk_alloc(g, va);
  if (!slot) return -1;
  __atomic_store_n(slot, desc, __ATOMIC_RELEASE);
  return 0;
}
static int pt_set_leaf_alloc_only(gmm_t *g, uint64_t va) { return pt_walk_alloc(g, va) ? 0 : GMM_ENOPT; }
// Wine M1 fix 1b: the leaf slot for `va` if every intermediate table already exists, else NULL. Never allocates.
static uint64_t *pt_lookup_slot(gmm_t *g, uint64_t va) {
  uint64_t t = g->root_ipa;
  for (int level = gmm_start_level_for_t0sz(g->cfg.t0sz); level < 3; level++) {
    const uint64_t e = pt_table_ptr(g, t)[(va >> (12 + 9 * (3 - level))) & 0x1FFull];
    if (!(e & 1ull)) return NULL;
    t = e & 0x0000fffffffff000ull;
  }
  return &pt_table_ptr(g, t)[(va >> 12) & 0x1FFull];
}
// Wine M1 fix 1b: allocate every intermediate table `va`'s leaf needs, without writing the leaf. Returns 0, or
// GMM_ENOPT if the pool ran out (tables allocated before that stay linked in: still-invalid leaves, reusable,
// never observable as a mapping). Every mutator calls this for every descriptor it may make valid BEFORE it
// changes anything, so a later pt_set_leaf() can no longer fail.
static int pt_ensure(gmm_t *g, uint64_t va) {
  if (pt_lookup_slot(g, va)) return 0;
  return pt_set_leaf_alloc_only(g, va);
}
static const void *pt_reader(void *ctx, uint64_t table_ipa) {
  gmm_t *g = (gmm_t *)ctx;
  if (table_ipa < g->cfg.pt_pool_ipa || table_ipa >= g->cfg.pt_pool_ipa + g->cfg.pt_pool_sz) return NULL;
  return pt_table_ptr(g, table_ipa);
}

// Writes `desc` at `va`, and — if the region containing `va` is a low4g region — also at the alias VA, with a
// trace event for each. `becoming_valid` selects which event kind is recorded (the caller already knows which
// transition this is; recomputing it from `desc` alone would be ambiguous for the RESERVED/DECOMMITTED/NOACCESS/
// GUARD tag distinctions the trace wants to preserve).
static inline uint64_t leaf_trace_ipa(uint64_t desc) {
  return (desc & 1ull) ? (desc & 0x0000fffffffff000ull) : ((desc >> GMM_TAG_SHIFT) & GMM_TAG_MASK);
}
// Wine M1 fix 1b: pt_set_leaf()'s -1 used to be ignored here (vprot said "committed", no PTE existed). Every
// caller now pt_ensure()s the path first and returns GMM_ENOPT before mutating anything, so a failure here is a
// broken internal invariant: stop loudly with every mapping left in place rather than continue inconsistent.
static void set_leaf_or_die(gmm_t *g, uint64_t va, uint64_t desc) {
  if (pt_set_leaf(g, va, desc) != 0) {
    fprintf(stderr, "gmm: BUG: PT pool exhausted writing va=0x%llx after pt_ensure() -- aborting\n",
            (unsigned long long)va);
    abort();
  }
}
static void write_leaf_both(gmm_t *g, gmm_region_t *r, uint64_t va, uint64_t desc, int becoming_valid) {
  set_leaf_or_die(g, va, desc);
  trace_push(g, becoming_valid ? GMM_EV_PTE_VALID : GMM_EV_PTE_INVALID, va, leaf_trace_ipa(desc));
  if (r->low4g) {
    uint64_t alias_va = va + g->cfg.alias_base;
    set_leaf_or_die(g, alias_va, desc);
    trace_push(g, becoming_valid ? GMM_EV_PTE_VALID : GMM_EV_PTE_INVALID, alias_va, leaf_trace_ipa(desc));
  }
}
// Ensures the tables for every page of [va, va+sz) of region r (and its alias twin). One lookup per 2 MiB span.
static int ensure_range(gmm_t *g, const gmm_region_t *r, uint64_t va, uint64_t sz) {
  for (uint64_t p = va; p < va + sz; p = (p | 0x1FFFFFull) + 1) {
    int rc = pt_ensure(g, p);
    if (!rc && r->low4g) rc = pt_ensure(g, p + g->cfg.alias_base);
    if (rc) return rc;
  }
  return 0;
}

// ================================================================================================================
// IPA allocator (§2).
// FAST MAPPING: contiguous ranges. First-fit over the free extents (lowest address), then the untouched top.
// Returns GMM_IPA_NONE if no free range of `n` contiguous chunks exists (there may still be n chunks in total).
static uint64_t alloc_ipa_range(gmm_t *g, uint64_t n) {
  const uint64_t sz = n * 16384;
  for (size_t i = 0; i < g->nifree; i++) {
    ipa_ext_t *e = &g->ifree[i];
    if (e->hi - e->lo < sz) continue;
    const uint64_t ipa = e->lo;
    e->lo += sz;
    if (e->lo == e->hi) {
      memmove(e, e + 1, (g->nifree - i - 1) * sizeof *e);
      g->nifree--;
    }
    return ipa;
  }
  if (g->ipa_bump + sz < g->ipa_bump || g->ipa_bump + sz > g->cfg.ipa_hi) return GMM_IPA_NONE;
  const uint64_t ipa = g->ipa_bump;
  g->ipa_bump += sz;
  return ipa;
}
// Returns [ipa, ipa + n*16K) to the allocator: sorted insert, coalesced with both neighbours, folded into the top
// if it reaches ipa_bump. Only ever called for a range that is provably NOT stage-2 mapped (never mapped, or after
// its s2_unmap returned) -- an IPA whose map FAILED is never freed (quarantined forever, GMM_ES2).
static void free_ipa_range(gmm_t *g, uint64_t ipa, uint64_t n) {
  uint64_t lo = ipa, hi = ipa + n * 16384;
  size_t i = 0;
  while (i < g->nifree && g->ifree[i].lo < lo) i++;
  if (i > 0 && g->ifree[i - 1].hi == lo) {  // merge into the previous extent
    i--;
    lo = g->ifree[i].lo;
    memmove(&g->ifree[i], &g->ifree[i + 1], (g->nifree - i - 1) * sizeof(ipa_ext_t));
    g->nifree--;
  }
  if (i < g->nifree && g->ifree[i].lo == hi) {  // merge with the next extent
    hi = g->ifree[i].hi;
    memmove(&g->ifree[i], &g->ifree[i + 1], (g->nifree - i - 1) * sizeof(ipa_ext_t));
    g->nifree--;
  }
  if (hi == g->ipa_bump) {  // reaches the untouched top: fold it back
    g->ipa_bump = lo;
    return;
  }
  if (g->nifree == g->capifree) {
    g->capifree = g->capifree ? g->capifree * 2 : 16;
    ipa_ext_t *ni = realloc(g->ifree, g->capifree * sizeof(ipa_ext_t));
    if (!ni) {  // cannot happen in practice (a few bytes); losing IPA space silently would be worse than stopping
      fprintf(stderr, "gmm: out of memory growing the IPA free list -- aborting\n");
      abort();
    }
    g->ifree = ni;
  }
  memmove(&g->ifree[i + 1], &g->ifree[i], (g->nifree - i) * sizeof(ipa_ext_t));
  g->ifree[i] = (ipa_ext_t){lo, hi};
  g->nifree++;
}
static uint64_t alloc_ipa(gmm_t *g) { return alloc_ipa_range(g, 1); }
static void free_ipa(gmm_t *g, uint64_t ipa) { free_ipa_range(g, ipa, 1); }
// How many single-chunk alloc_ipa() calls are guaranteed to succeed right now (pre-check, Wine M1 fix 1b). An IPA
// whose map FAILED is never freed (quarantined forever, GMM_ES2), so it is simply not counted here.
static uint64_t ipa_available(const gmm_t *g) {
  uint64_t n = (g->cfg.ipa_hi - g->ipa_bump) / 16384;
  for (size_t i = 0; i < g->nifree; i++) n += (g->ifree[i].hi - g->ifree[i].lo) / 16384;
  return n;
}

// ================================================================================================================
// TLBI batching helper: gathers up to two VAs (canonical + alias) per touched page into a caller-owned scratch
// buffer; flushed by the caller with one backend->tlbi_sync() call, matching "who executes the TLBI" (§2): one
// executor, one batched `tlbi vale1is x n`, synchronous completion under the gmm mutex.
// Above this many VAs one call asks for the whole-VMID flush instead (§2: "vmalle1is if >64"). No G-run's batch
// comes near it (G5's is 8); Wine's large decommits/view deletes will.
#define GMM_TLBI_BATCH_MAX 64
static void do_tlbi(gmm_t *g, const uint64_t *va, size_t n) {
  trace_push(g, GMM_EV_TLBI, n ? va[0] : 0, n);
  const int all = n > GMM_TLBI_BATCH_MAX;
  if (g->backend.tlbi_sync(g->backend.ctx, all ? NULL : va, all ? 0 : n, all) != 0) {
    // G5 review: a revocation must never proceed past a failed shootdown (zero/unmap/free would follow). Stop the
    // process with everything still mapped rather than free memory a stale translation may still reach.
    fprintf(stderr, "gmm: tlbi_sync FAILED (n=%zu) -- aborting with every mapping left in place\n", n);
    abort();
  }
}

// ================================================================================================================
// apply_page: the shared valid<->valid / valid<->invalid PTE-transition decision for gmm_commit/gmm_protect (§2
// revocation order items "guard arm, prot lowering, OA change" for the lowering side; invalid->valid needs no
// TLBI at all). gmm_decommit does NOT use this — it always needs the fuller chunk-lifecycle ladder and writes a
// GMM_TAG_DECOMMITTED descriptor directly (see gmm_decommit).
//
// DESIGN NOTE (found during implementation, not fully specified by DESIGN-guest-memory-manager.md §2): the design
// distinguishes GMM_F_RETRY from GMM_F_RETRY_LOCAL_TLBI in gmm_fault's return values but does not say which
// PTE-transition triggers which, nor precisely which "permission raise" needs the local-TLBI retry protocol vs.
// which needs a real TLBI up front. The rule implemented here (see also gmm_fault below):
//   - invalid -> valid (commit of a fresh page, guard clearing): no TLBI, ever (architecturally safe: an entry
//     that was never cached as valid cannot be behind a stale walk).
//   - valid -> invalid, or valid -> valid with the new descriptor MORE restrictive in any dimension (AP2 0->1,
//     PXN 0->1): TLBI issued eagerly, before the caller's PTE write is allowed to be observed as "done" — a
//     stricter access must never spuriously succeed against a stale looser cached translation.
//   - valid -> valid with the new descriptor STRICTLY LESS restrictive (a permission "raise", e.g. write-watch
//     clearing, or RO->RW): no TLBI up front (§2 explicitly asks for this: "Permission raise: no TLBI up front").
//     A vCPU whose TLB still holds the old, stricter entry then takes a spurious permission fault; gmm_fault
//     recognises (by re-deriving intent from vprot, which this function has ALREADY updated) that the access
//     should now succeed, and returns GMM_F_RETRY_LOCAL_TLBI so the guest's own vector does a local `TLBI VALE1`
//     and retries — this is the mechanism §2 describes but does not name as a specific enum-value mapping.
// Whether a raise should EVER need the eager/synchronous TLBI (e.g. because some other vCPU's TLB caches a
// stricter entry it will never itself re-fault on, because it never tries the now-newly-permitted access) is,
// per §2's own text, an accepted trade — correctness relies on every vCPU re-deriving permission on its OWN
// fault, not on a global invariant that all TLBs are eventually flushed proactively. That is a real, load-bearing
// assumption this prototype inherited from the design rather than one it introduced.
//
// WINE M1 (2026-09-23): the rule above is now the LEGACY policy, behind GMM_CFG_LAZY_RAISE_TLBI. The default is
// EAGER: every change to a descriptor that was valid is shot down before the call returns -- raises included --
// because Wine's M1 vector forwards every fault to the host, and the host cannot TLBI on the faulting vCPU (the
// RETRY_LOCAL_TLBI protocol has no executor there). invalid->valid stays TLBI-free in both policies.
static int valid_change_needs_tlbi(const gmm_t *g, uint64_t old_desc, uint64_t new_desc) {
  if (!(old_desc & 1ull) || old_desc == new_desc) return 0;  // nothing cached, or nothing changed
  if (!(g->cfg.flags & GMM_CFG_LAZY_RAISE_TLBI)) return 1;    // eager: every change to a valid descriptor
  if (!(new_desc & 1ull)) return 1;                            // valid -> invalid
  gmm_xlat_t oa, na;
  gmm_pte_decode_leaf(old_desc, &oa);
  gmm_pte_decode_leaf(new_desc, &na);
  if (oa.ipa != na.ipa) return 1;                                // output address change (never a "raise")
  return (na.ap_ro && !oa.ap_ro) || (na.pxn && !oa.pxn);        // legacy: only a lowering
}
static void apply_page(gmm_t *g, gmm_region_t *r, uint64_t page_va, unsigned idx, int old_committed,
                        unsigned old_prot, unsigned old_overlay, unsigned new_prot, unsigned new_overlay,
                        uint64_t ipa) {
  const uint64_t old_desc = old_committed ? gmm_pte_encode(old_prot, old_overlay, ipa) : 0;
  const uint64_t new_desc = gmm_pte_encode(new_prot, new_overlay, ipa);
  const int old_valid = (old_desc & 1ull) != 0;
  const int new_valid = (new_desc & 1ull) != 0;

  r->vprot[idx] = vp_make(1, new_prot, new_overlay);

  if (old_committed && old_desc == new_desc) return;  // true no-op: nothing to write or flush

  if (!old_valid && new_valid) {
    write_leaf_both(g, r, page_va, new_desc, 1);
    return;
  }
  if (old_valid && !new_valid) {
    write_leaf_both(g, r, page_va, new_desc, 0);
    uint64_t va[2] = {page_va, page_va + g->cfg.alias_base};
    do_tlbi(g, va, r->low4g ? 2 : 1);
    return;
  }
  if (!old_valid && !new_valid) {
    write_leaf_both(g, r, page_va, new_desc, 0);  // tag-only change (e.g. NOACCESS<->GUARD); no TLBI, still invalid
    return;
  }
  // old_valid && new_valid (and old_desc != new_desc).
  write_leaf_both(g, r, page_va, new_desc, 1);
  if (valid_change_needs_tlbi(g, old_desc, new_desc)) {
    uint64_t va[2] = {page_va, page_va + g->cfg.alias_base};
    do_tlbi(g, va, r->low4g ? 2 : 1);
  }
  // else (legacy policy only): pure raise, no TLBI up front (see the DESIGN NOTE above).
}

void *gmm_alloc_backing(size_t sz) { return gmm_host_alloc(sz); }
void gmm_free_backing(void *p, size_t sz) { gmm_host_free(p, sz); }
int gmm_debug_tag_flag(void) { return gmm_tag_flag(); }

// ================================================================================================================
// gmm_init / gmm_destroy.
int gmm_init(gmm_t **out, const gmm_config_t *cfg, const gmm_backend_t *backend) {
  if (!out || !cfg || !backend || !backend->s2_map || !backend->s2_unmap || !backend->tlbi_sync) return -1;
  if (!cfg->pt_pool_host || cfg->pt_pool_sz < 4096 || (cfg->pt_pool_sz % 4096) != 0) return -1;
  if (cfg->ipa_hi <= cfg->ipa_lo || (cfg->ipa_lo % 16384) != 0 || (cfg->ipa_hi % 16384) != 0) return -1;

  gmm_t *g = calloc(1, sizeof(gmm_t));
  if (!g) return -1;
  g->cfg = *cfg;
  g->backend = *backend;
  pthread_mutex_init(&g->mtx, NULL);
  g->ipa_bump = cfg->ipa_lo;

  // PT pool: one anon pool, s2_map'd once before any vCPU (GuestMirror::Init() pattern, §2).
  if (gmm_backing_check(cfg->pt_pool_host, cfg->pt_pool_sz) != 0) {
    // The caller-supplied pool must ALSO satisfy the backing guard (it is memory that will be handed to
    // hv_vm_map by a live backend): fail rather than abort here, since gmm_init has a clean error path and the
    // caller may want to retry with a correctly-tagged allocation.
    pthread_mutex_destroy(&g->mtx);
    free(g);
    return -1;
  }
  uint32_t r = backend->s2_map(cfg->pt_pool_host, cfg->pt_pool_ipa, cfg->pt_pool_sz, GMM_S2_R | GMM_S2_W);
  if (r != 0) { // G1 review: never build tables into a pool the VM cannot see
    pthread_mutex_destroy(&g->mtx);
    free(g);
    return -1;
  }
  g->root_ipa = pt_alloc_table(g);
  if (g->root_ipa == GMM_IPA_NONE) {
    pthread_mutex_destroy(&g->mtx);
    free(g);
    return -1;
  }
  *out = g;
  return 0;
}

void gmm_destroy(gmm_t *g) {
  if (!g) return;
  for (size_t i = 0; i < g->nregions; i++) {
    free(g->regions[i].vprot);
    if (g->regions[i].chunks) {
      for (size_t c = 0; c < g->regions[i].size / 16384; c++)
        if (g->regions[i].chunks[c].host) gmm_host_free(g->regions[i].chunks[c].host, 16384);
      free(g->regions[i].chunks);
    }
  }
  free(g->regions);
  free(g->thin.slots);  // thin chunks' host memory is the caller's: nothing to unmap here
  free(g->ifree);
  free(g->recs);
  free(g->trace);
  pthread_mutex_destroy(&g->mtx);
  free(g);
}

uint64_t gmm_ttbr0(gmm_t *g) { return g->root_ipa; }

// ================================================================================================================
// gmm_reserve.
int gmm_reserve(gmm_t *g, uint64_t va, size_t sz, unsigned flags) {
  if (sz == 0 || (va % 65536) != 0 || (sz % 65536) != 0) return -1;
  pthread_mutex_lock(&g->mtx);
  int rc = -1;
  if ((flags & GMM_RESERVE_LOW4G) && !g->cfg.alias_base) goto out;
  if (g->cfg.alias_base) {
    const uint64_t win_lo = g->cfg.alias_base, win_hi = g->cfg.alias_base + 0x100000000ull;
    int outside = (va + sz <= win_lo) || (va >= win_hi);
    if (!outside) goto out;  // never allow an allocation to touch the alias window itself
    if ((flags & GMM_RESERVE_LOW4G) && va + sz > 0x100000000ull) goto out;  // must stay <4GiB canonical (G6 review: was alias_base)
  }
  if (regions_overlap(g, va, sz)) goto out;
  if (tchunk_any_in(&g->thin, va, sz)) goto out;  // Wine M1: never over committed thin/identity memory

  gmm_region_t rec = {0};
  rec.base = va;
  rec.size = sz;
  rec.type = GMM_TYPE_PRIVATE;
  rec.low4g = (flags & GMM_RESERVE_LOW4G) != 0;
  rec.vprot = calloc(sz / 4096, sizeof(uint16_t));
  rec.chunks = calloc(sz / 16384, sizeof(gmm_chunk_t));
  if (!rec.vprot || !rec.chunks) {
    free(rec.vprot);
    free(rec.chunks);
    goto out;
  }
  for (size_t i = 0; i < sz / 16384; i++) rec.chunks[i].ipa = GMM_IPA_NONE;
  region_insert(g, rec);
  rc = 0;
out:
  pthread_mutex_unlock(&g->mtx);
  return rc;
}

// ================================================================================================================
// gmm_commit.
int gmm_commit(gmm_t *g, uint64_t va, size_t sz, uint32_t page_prot) {
  if (sz == 0 || (va % 4096) != 0 || (sz % 4096) != 0) return -1;
  pthread_mutex_lock(&g->mtx);
  int rc = -1;
  gmm_region_t *r = find_region(g, va);
  if (!r || r->type != GMM_TYPE_PRIVATE || va + sz > r->base + r->size) goto out;

  const size_t first_idx = (va - r->base) / 4096;
  const size_t npages = sz / 4096;
  // ---- Wine M1 fix 1b: reserve every resource before mutating anything, so a failure leaves NO half-applied
  // state (before: a PT-pool/host-alloc/IPA failure mid-loop left earlier pages committed, and pt_set_leaf's -1
  // was ignored so vprot could say "committed" with no PTE). Order: tables, then host chunks, then IPAs.
  {
    const size_t c_first = (va - r->base) / 16384, c_last = (va + sz - 1 - r->base) / 16384;
    if ((rc = ensure_range(g, r, va, sz)) != 0) goto out;
    size_t need_ipa = 0;
    for (size_t ci = c_first; ci <= c_last; ci++)
      if (!r->chunks[ci].s2_mapped) need_ipa++;  // !s2_mapped <=> no committed page in it (refs 0)
    if (ipa_available(g) < need_ipa) {
      rc = GMM_ENOIPA;
      goto out;
    }
    for (size_t ci = c_first; ci <= c_last; ci++) {
      gmm_chunk_t *c = &r->chunks[ci];
      if (c->host) continue;
      c->host = gmm_host_alloc(16384);
      if (!c->host) {  // undo only this call's allocations: those chunks have no committed page, so no mapping
        for (size_t cj = c_first; cj < ci; cj++)
          if (r->chunks[cj].host && !r->chunks[cj].s2_mapped && r->chunks[cj].refs == 0) {
            gmm_host_free(r->chunks[cj].host, 16384);
            r->chunks[cj].host = NULL;
          }
        rc = GMM_ENOMEM;
        goto out;
      }
      c->ipa = GMM_IPA_NONE;
      c->s2_mapped = 0;
      c->refs = 0;
    }
    rc = -1;
  }
  for (size_t p = 0; p < npages; p++) {
    const uint64_t page_va = va + p * 4096;
    const size_t idx = first_idx + p;
    const size_t cidx = (page_va - r->base) / 16384;
    gmm_chunk_t *c = &r->chunks[cidx];
    const int was_committed = vp_committed(r->vprot[idx]);

    if (!was_committed) {
      c->refs++;
      if (!c->s2_mapped) {
        if (gmm_backing_check(c->host, 16384) != 0) abort();  // §2: abort, never silently proceed
        c->ipa = alloc_ipa(g);
        if (c->ipa == GMM_IPA_NONE) abort();                     // pre-checked above: cannot happen
        uint32_t sr = g->backend.s2_map(c->host, c->ipa, 16384, GMM_S2_RWX);
        if (sr != 0) abort(); // G1 review: a PTE must never point at an IPA stage-2 does not back
        trace_push(g, GMM_EV_S2_MAP, page_va & ~(uint64_t)16383, c->ipa);
        c->s2_mapped = 1;
      }
    }

    const uint64_t offset_in_chunk = page_va - (r->base + cidx * 16384);
    const uint64_t page_ipa = c->ipa + offset_in_chunk;
    const unsigned old_prot = vp_prot(r->vprot[idx]);
    const unsigned old_overlay = vp_overlay(r->vprot[idx]);
    apply_page(g, r, page_va, idx, was_committed, old_prot, old_overlay, page_prot, 0 /* fresh overlay on commit */,
               page_ipa);
  }
  rc = 0;
out:
  pthread_mutex_unlock(&g->mtx);
  return rc;
}

// ================================================================================================================
// gmm_decommit: the full revocation ladder (§2 items 1-5), batched: all PTE invalidations first, one TLBI call,
// then per-page zeroing and per-chunk stage-2 unmap/host-free for chunks whose refcount reaches 0.
//
// Factored out of the public entry point so gmm_release() can call it directly, under the SAME mutex acquisition
// and the SAME gmm_region_t*, for every run of committed pages in the region it is releasing. Calling back into
// the public gmm_decommit() (lock/find_region/unlock) instead would require dropping the lock between calls,
// during which another thread's region_insert()/region_remove() may realloc() g->regions and invalidate every
// gmm_region_t* — including the one gmm_release is holding. That hazard is exactly the kind of thing N8 exists to
// catch; it showed up during implementation, not in the design doc, and is recorded in the final report.
static int decommit_locked(gmm_t *g, gmm_region_t *r, uint64_t va, size_t sz) {
  if (va + sz > r->base + r->size) return -1;
  const size_t first_idx = (va - r->base) / 4096;
  const size_t npages = sz / 4096;
  for (size_t p = 0; p < npages; p++)
    if (!vp_committed(r->vprot[first_idx + p])) return -1;  // caller bug: decommitting a non-committed page

  // Step 1: invalid+tag descriptor, both aliases, for every page.
  for (size_t p = 0; p < npages; p++) {
    const uint64_t page_va = va + p * 4096;
    const size_t idx = first_idx + p;
    const uint64_t inv = (uint64_t)GMM_TAG_DECOMMITTED << GMM_TAG_SHIFT;
    write_leaf_both(g, r, page_va, inv, 0);
    r->vprot[idx] = vp_make(0, 0, 0);
  }
  // Step 2: one batched TLBI covering every touched VA (both aliases).
  {
    const size_t stride = r->low4g ? 2 : 1;
    uint64_t *vas = malloc(npages * stride * sizeof(uint64_t));
    for (size_t p = 0; p < npages; p++) {
      vas[p * stride] = va + p * 4096;
      if (r->low4g) vas[p * stride + 1] = va + p * 4096 + g->cfg.alias_base;
    }
    do_tlbi(g, vas, npages * stride);
    free(vas);
  }
  // Steps 3-5: zero each page, then unmap/free any chunk whose refcount just hit 0.
  for (size_t p = 0; p < npages; p++) {
    const uint64_t page_va = va + p * 4096;
    const size_t cidx = (page_va - r->base) / 16384;
    gmm_chunk_t *c = &r->chunks[cidx];
    const uint64_t off = page_va - (r->base + cidx * 16384);
    memset((uint8_t *)c->host + off, 0, 4096);
    trace_push(g, GMM_EV_ZERO, page_va, 0);
    c->refs--;
    if (c->refs == 0) {
      uint32_t sr = g->backend.s2_unmap(c->ipa, 16384);
      if (sr != 0) {
        // G5 review: never free_ipa/munmap a chunk that may still be stage-2 mapped (mirrors s2_map's abort).
        fprintf(stderr, "gmm: s2_unmap(ipa=0x%llx) FAILED 0x%x -- aborting with the chunk left mapped\n",
                (unsigned long long)c->ipa, sr);
        abort();
      }
      trace_push(g, GMM_EV_S2_UNMAP, page_va & ~(uint64_t)16383, c->ipa);
      free_ipa(g, c->ipa);  // quarantine -> free: only now, strictly after the TLBI above has returned
      gmm_host_free(c->host, 16384);
      c->host = NULL;
      c->ipa = GMM_IPA_NONE;
      c->s2_mapped = 0;
    }
  }
  return 0;
}

int gmm_decommit(gmm_t *g, uint64_t va, size_t sz) {
  if (sz == 0 || (va % 4096) != 0 || (sz % 4096) != 0) return -1;
  pthread_mutex_lock(&g->mtx);
  int rc = -1;
  gmm_region_t *r = find_region(g, va);
  if (r && r->type == GMM_TYPE_PRIVATE) rc = decommit_locked(g, r, va, sz);
  pthread_mutex_unlock(&g->mtx);
  return rc;
}

// ================================================================================================================
// gmm_release: decommit every still-committed page in the region (freeing all backing), then drop the record.
// One lock acquisition, one gmm_region_t*, for the whole operation (see decommit_locked's comment).
int gmm_release(gmm_t *g, uint64_t alloc_base) {
  pthread_mutex_lock(&g->mtx);
  int rc = -1;
  gmm_region_t *r = find_region_exact(g, alloc_base);
  if (!r || r->type != GMM_TYPE_PRIVATE) goto out;

  {
    const size_t npages = r->size / 4096;
    size_t p = 0;
    int bad = 0;
    while (p < npages) {
      if (!vp_committed(r->vprot[p])) {
        p++;
        continue;
      }
      size_t run = 1;
      while (p + run < npages && vp_committed(r->vprot[p + run])) run++;
      if (decommit_locked(g, r, r->base + p * 4096, run * 4096) != 0) {
        bad = 1;
        break;
      }
      p += run;
    }
    if (bad) goto out;
  }
  region_remove(g, r);
  rc = 0;
out:
  pthread_mutex_unlock(&g->mtx);
  return rc;
}

// ================================================================================================================
// gmm_protect.
int gmm_protect(gmm_t *g, uint64_t va, size_t sz, uint32_t prot, uint32_t *old) {
  if (sz == 0 || (va % 4096) != 0 || (sz % 4096) != 0) return -1;
  pthread_mutex_lock(&g->mtx);
  int rc = -1;
  gmm_region_t *r = find_region(g, va);
  if (!r || va + sz > r->base + r->size) goto out;

  const size_t first_idx = (va - r->base) / 4096;
  const size_t npages = sz / 4096;
  for (size_t p = 0; p < npages; p++)
    if (!vp_committed(r->vprot[first_idx + p])) goto out;
  // Wine M1 fix 1b: every committed page already has its tables (commit wrote a leaf for it), so this cannot fail
  // today; it is here so a protect can never half-apply if that ever stops being true.
  if ((rc = ensure_range(g, r, va, sz)) != 0) goto out;
  rc = -1;
  if (old) *old = vp_prot(r->vprot[first_idx]);

  for (size_t p = 0; p < npages; p++) {
    const uint64_t page_va = va + p * 4096;
    const size_t idx = first_idx + p;
    const size_t cidx = (page_va - r->base) / 16384;
    const unsigned old_prot = vp_prot(r->vprot[idx]);
    const unsigned overlay = vp_overlay(r->vprot[idx]);  // gmm_protect never touches overlay bits
    uint64_t page_ipa;
    if (r->type == GMM_TYPE_PRIVATE) {
      const uint64_t off = page_va - (r->base + cidx * 16384);
      page_ipa = r->chunks[cidx].ipa + off;
    } else {
      const size_t sidx = (r->view_off + (page_va - r->base)) / 16384;
      const uint64_t off = (r->view_off + (page_va - r->base)) - sidx * 16384;
      page_ipa = r->section->ipa[sidx] + off;
    }
    apply_page(g, r, page_va, idx, 1, old_prot, overlay, prot, overlay, page_ipa);
  }
  rc = 0;
out:
  pthread_mutex_unlock(&g->mtx);
  return rc;
}

// ================================================================================================================
// Sections + views (§2 "Backing guard: Sections").
int gmm_section_create(gmm_t *g, size_t sz, gmm_section_t **out) {
  if (sz == 0 || !out) return -1;
  pthread_mutex_lock(&g->mtx);
  int rc = -1;
  gmm_section_t *s = calloc(1, sizeof(gmm_section_t));
  if (!s) goto out;
  s->size = (sz + 16383) & ~(size_t)16383;
  s->nchunks = s->size / 16384;
  s->host = calloc(s->nchunks, sizeof(void *));
  s->ipa = calloc(s->nchunks, sizeof(uint64_t));
  if (!s->host || !s->ipa) goto fail;
  if (ipa_available(g) < s->nchunks) {  // Wine M1 fix 1b: pre-check, no partial section
    rc = GMM_ENOIPA;
    goto fail;
  }
  for (size_t i = 0; i < s->nchunks; i++) {
    s->host[i] = gmm_host_alloc(16384);
    if (!s->host[i]) {
      rc = GMM_ENOMEM;
      goto fail;
    }
  }
  for (size_t i = 0; i < s->nchunks; i++) {
    if (gmm_backing_check(s->host[i], 16384) != 0) abort();
    s->ipa[i] = alloc_ipa(g);  // pre-checked: cannot fail
    uint32_t sr = g->backend.s2_map(s->host[i], s->ipa[i], 16384, GMM_S2_RWX);
    if (sr != 0) {
      // Wine M1 fix 1c: the result used to be ignored (gmm_commit aborts in the same spot). Fail cleanly instead,
      // under the G5 review rule "never free possibly-mapped memory": no view exists yet, so no descriptor
      // references any of these IPAs and no TLBI is needed; unmap every chunk this call mapped (abort if that
      // fails), then free those. The chunk whose map FAILED may be partly mapped: its host memory is leaked on
      // purpose and its IPA is never returned to the allocator.
      fprintf(stderr, "gmm: section s2_map(ipa=0x%llx) failed 0x%x -- rolling back %zu chunk(s), quarantining it\n",
              (unsigned long long)s->ipa[i], sr, i);
      for (size_t j = 0; j < i; j++) {
        if (g->backend.s2_unmap(s->ipa[j], 16384) != 0) {
          fprintf(stderr, "gmm: rollback s2_unmap(ipa=0x%llx) FAILED -- aborting with it mapped\n",
                  (unsigned long long)s->ipa[j]);
          abort();
        }
        trace_push(g, GMM_EV_S2_UNMAP, 0, s->ipa[j]);
        free_ipa(g, s->ipa[j]);
      }
      s->host[i] = NULL;  // quarantined: never freed (see above)
      rc = GMM_ES2;
      goto fail;
    }
    trace_push(g, GMM_EV_S2_MAP, 0, s->ipa[i]);
  }
  *out = s;
  rc = 0;
  goto out;
fail:
  if (s) {
    if (s->host)
      for (size_t i = 0; i < s->nchunks; i++)
        if (s->host[i]) gmm_host_free(s->host[i], 16384);  // only never-mapped or cleanly-unmapped chunks
    free(s->host);
    free(s->ipa);
    free(s);
  }
out:
  pthread_mutex_unlock(&g->mtx);
  return rc;
}

int gmm_map_view(gmm_t *g, gmm_section_t *section, uint64_t off, uint64_t va, size_t sz, uint32_t prot,
                  unsigned flags) {
  if (!section || sz == 0 || (va % 4096) != 0 || (sz % 4096) != 0 || (off % 4096) != 0) return -1;
  if (off + sz > section->size) return -1;
  pthread_mutex_lock(&g->mtx);
  int rc = -1;
  // G6 addition (see gmm.h's comment on this function): GMM_RESERVE_LOW4G here means EXACTLY what it means for
  // gmm_reserve() -- `va` must be a canonical <4GiB address, entirely below the alias window, and gmm auto-mirrors
  // this view at alias_base+va (rec.low4g below drives write_leaf_both, gmm.c, the SAME mechanism a low4g PRIVATE
  // region already uses). Without the flag (flags==0), a view may never touch the alias window at all -- unchanged
  // from every prior gmm_map_view behaviour (untested before G6; G1-G5 never called this function).
  if ((flags & GMM_RESERVE_LOW4G) && !g->cfg.alias_base) goto out;
  if (g->cfg.alias_base) {
    const uint64_t win_lo = g->cfg.alias_base, win_hi = g->cfg.alias_base + 0x100000000ull;
    const int outside = (va + sz <= win_lo) || (va >= win_hi);
    if (flags & GMM_RESERVE_LOW4G) {
      if (va + sz > 0x100000000ull) goto out;  // must stay entirely <4GiB canonical (G6 review: was win_lo = alias_base)
    } else if (!outside) {
      goto out;  // non-low4g view: never allowed to touch the alias window itself
    }
  } else if (flags & GMM_RESERVE_LOW4G) {
    goto out;  // no alias_base configured: low4g flag is meaningless, refuse rather than silently ignore it
  }
  if (regions_overlap(g, va, sz)) goto out;
  if (tchunk_any_in(&g->thin, va, sz)) goto out;  // Wine M1: never over committed thin/identity memory

  gmm_region_t rec = {0};
  rec.base = va;
  rec.size = sz;
  rec.type = GMM_TYPE_MAPPED;
  rec.alloc_prot = prot;
  rec.low4g = (flags & GMM_RESERVE_LOW4G) != 0;
  rec.section = section;
  rec.view_off = off;
  // Wine M1 fix 1b: every table the view's descriptors need, before the region exists at all.
  if ((rc = ensure_range(g, &rec, va, sz)) != 0) goto out;
  rc = -1;
  rec.vprot = calloc(sz / 4096, sizeof(uint16_t));
  if (!rec.vprot) goto out;
  gmm_region_t *r = region_insert(g, rec);

  const size_t npages = sz / 4096;
  for (size_t p = 0; p < npages; p++) {
    const uint64_t page_va = va + p * 4096;
    const uint64_t soff = off + p * 4096;
    const size_t sidx = soff / 16384;
    const uint64_t page_ipa = section->ipa[sidx] + (soff - sidx * 16384);
    apply_page(g, r, page_va, p, 0, 0, 0, prot, 0, page_ipa);
  }
  rc = 0;
out:
  pthread_mutex_unlock(&g->mtx);
  return rc;
}

int gmm_unmap_view(gmm_t *g, uint64_t va) {
  pthread_mutex_lock(&g->mtx);
  int rc = -1;
  gmm_region_t *r = find_region_exact(g, va);
  if (!r || r->type != GMM_TYPE_MAPPED) goto out;

  const size_t npages = r->size / 4096;
  const size_t stride = r->low4g ? 2 : 1;
  uint64_t *vas = malloc(npages * stride * sizeof(uint64_t));
  for (size_t p = 0; p < npages; p++) {
    const uint64_t page_va = r->base + p * 4096;
    const uint64_t inv = (uint64_t)GMM_TAG_RESERVED << GMM_TAG_SHIFT;
    write_leaf_both(g, r, page_va, inv, 0);
    vas[p * stride] = page_va;
    if (r->low4g) vas[p * stride + 1] = page_va + g->cfg.alias_base;
  }
  do_tlbi(g, vas, npages * stride);
  free(vas);
  // The section's backing/stage-2 mapping is untouched — other views (or future ones) may still reference it.
  region_remove(g, r);
  rc = 0;
out:
  pthread_mutex_unlock(&g->mtx);
  return rc;
}

// TEST/CALLER SUPPORT (gmm.h, added for G6): a section's chunk array is fixed for its whole lifetime once
// gmm_section_create() returns (no gmm_section_destroy exists; sections are never freed in this prototype), so
// this needs no locking against gmm_t's mutex — unlike gmm_host_ptr(), which reads a region that a concurrent
// gmm_reserve()/gmm_release() could still be mutating.
void *gmm_section_host_ptr(gmm_section_t *section, uint64_t off) {
  if (!section || off >= section->size) return NULL;
  const size_t cidx = off / 16384;
  return (uint8_t *)section->host[cidx] + (off - cidx * 16384);
}

// ================================================================================================================
// gmm_query / gmm_host_ptr / gmm_set_overlay.
int gmm_query(gmm_t *g, uint64_t va, gmm_mbi_t *out) {
  pthread_mutex_lock(&g->mtx);
  va = dealias(g, va);
  gmm_region_t *r = find_region(g, va);
  if (!r) {
    pthread_mutex_unlock(&g->mtx);
    return -1;
  }
  const size_t idx = (va - r->base) / 4096;
  const uint16_t vp = r->vprot[idx];
  out->base_address = r->base + idx * 4096;
  out->allocation_base = r->base;
  out->allocation_protect = r->alloc_prot;
  out->type = r->type;
  if (r->type == GMM_TYPE_MAPPED) {
    out->state = GMM_STATE_COMMIT;
    out->protect = vp_prot(vp);
  } else if (vp_committed(vp)) {
    out->state = GMM_STATE_COMMIT;
    out->protect = vp_prot(vp);
  } else {
    out->state = GMM_STATE_RESERVE;
    out->protect = 0;
  }
  // region_size: run of pages from idx sharing the same (committed, prot) pair, for a same-region MBI query
  // caller could reasonably want. Kept simple/O(n) — fine for a prototype/test harness.
  size_t end = idx;
  while (end + 1 < r->size / 4096 && r->vprot[end + 1] == vp) end++;
  out->region_size = (end - idx + 1) * 4096;
  pthread_mutex_unlock(&g->mtx);
  return 0;
}

void *gmm_host_ptr(gmm_t *g, uint64_t va) {
  pthread_mutex_lock(&g->mtx);
  va = dealias(g, va);
  gmm_region_t *r = find_region(g, va);
  void *p = NULL;
  if (r) {
    const size_t idx = (va - r->base) / 4096;
    if (r->type == GMM_TYPE_PRIVATE && vp_committed(r->vprot[idx])) {
      const size_t cidx = idx / 4;
      if (r->chunks[cidx].host) p = (uint8_t *)r->chunks[cidx].host + (va - (r->base + cidx * 16384));
    } else if (r->type == GMM_TYPE_MAPPED) {
      const uint64_t soff = r->view_off + (va - r->base);
      const size_t sidx = soff / 16384;
      p = (uint8_t *)r->section->host[sidx] + (soff - sidx * 16384);
    }
  } else {
    // Wine M1 thin/identity memory: the host pointer IS the VA, while the 4K page is committed.
    const tchunk_t *c = tchunk_find(&g->thin, va & ~16383ull);
    if (c && (c->committed & (1u << ((va >> 12) & 3)))) p = (void *)(uintptr_t)va;
  }
  pthread_mutex_unlock(&g->mtx);
  return p;
}

int gmm_set_overlay(gmm_t *g, uint64_t va, size_t sz, unsigned set, unsigned clr) {
  if (sz == 0 || (va % 4096) != 0 || (sz % 4096) != 0) return -1;
  pthread_mutex_lock(&g->mtx);
  int rc = -1;
  gmm_region_t *r = find_region(g, va);
  if (!r || va + sz > r->base + r->size) goto out;
  const size_t first_idx = (va - r->base) / 4096;
  const size_t npages = sz / 4096;
  for (size_t p = 0; p < npages; p++)
    if (!vp_committed(r->vprot[first_idx + p])) goto out;

  for (size_t p = 0; p < npages; p++) {
    const uint64_t page_va = va + p * 4096;
    const size_t idx = first_idx + p;
    const size_t cidx = (page_va - r->base) / 16384;
    const unsigned old_prot = vp_prot(r->vprot[idx]);
    const unsigned old_overlay = vp_overlay(r->vprot[idx]);
    const unsigned new_overlay = (old_overlay | set) & ~clr;
    if (new_overlay == old_overlay) continue;
    uint64_t page_ipa;
    if (r->type == GMM_TYPE_PRIVATE) {
      const uint64_t off = page_va - (r->base + cidx * 16384);
      page_ipa = r->chunks[cidx].ipa + off;
    } else {
      const size_t sidx = (r->view_off + (page_va - r->base)) / 16384;
      const uint64_t off = (r->view_off + (page_va - r->base)) - sidx * 16384;
      page_ipa = r->section->ipa[sidx] + off;
    }
    apply_page(g, r, page_va, idx, 1, old_prot, old_overlay, old_prot, new_overlay, page_ipa);
  }
  rc = 0;
out:
  pthread_mutex_unlock(&g->mtx);
  return rc;
}

// ================================================================================================================
// gmm_fault (§0/§2). Classifies from the region tree / vprot (the source of truth for INTENDED state), not by
// re-walking the page tables — a real fault handler has the same information available without a walk, and using
// vprot lets gmm_fault detect "someone else already fixed this concurrently" (see the DESIGN NOTE above apply_page
// and the GMM_F_RETRY case below) directly from a value that is itself always current under the mutex.
// Wine M1 fix 1a helpers, shared with gmm_vm_fault. EC: 0x20/0x21 instruction abort from a lower/the same EL,
// 0x24/0x25 data abort from a lower/the same EL -- nothing else is a memory abort. ESR.FnV (bit 10) = FAR not valid.
static int esr_is_memory_abort(uint64_t esr) {
  const unsigned ec = (unsigned)(esr >> 26);
  return ec == 0x20 || ec == 0x21 || ec == 0x24 || ec == 0x25;
}
static int dfsc_is_translation(unsigned dfsc) { return dfsc >= 0x04 && dfsc <= 0x07; }  // levels 0..3
// gmm builds level-3 page descriptors only (no blocks), so a permission fault can only be a level-3 one.
static int dfsc_is_l3_permission(unsigned dfsc) { return dfsc == 0x0F; }

gmm_fault_t gmm_fault(gmm_t *g, uint64_t far, uint64_t esr) {
  // Classification preconditions first (Wine M1 fix 1a): not a memory abort, FAR not valid, or a DFSC gmm's own
  // tables can never legitimately produce (access flag, address size, block-level permission, external abort...)
  // are broken invariants, not guest faults.
  if (!esr_is_memory_abort(esr) || (esr & (1ull << 10))) return GMM_F_BUG;
  if (!dfsc_is_translation((unsigned)(esr & 0x3F)) && !dfsc_is_l3_permission((unsigned)(esr & 0x3F))) return GMM_F_BUG;
  // Legacy policy: the guest vector retries after a LOCAL tlbi. Eager (default): the raise's shootdown has already
  // completed (it ran under this same mutex), so a plain retry is enough.
  const gmm_fault_t RETRY_STALE =
      (g->cfg.flags & GMM_CFG_LAZY_RAISE_TLBI) ? GMM_F_RETRY_LOCAL_TLBI : GMM_F_RETRY;
  pthread_mutex_lock(&g->mtx);
  const uint64_t va = dealias(g, far);
  const unsigned ec = (unsigned)(esr >> 26);
  const unsigned dfsc = (unsigned)(esr & 0x3F);
  const int wnr = (int)((esr >> 6) & 1);
  gmm_fault_t result;

  gmm_region_t *r = find_region(g, va);
  if (!r) {
    result = GMM_F_AV;
    goto out;
  }
  const size_t idx = (va - r->base) / 4096;
  const size_t cidx = idx / 4;
  const uint16_t vp = r->vprot[idx];
  const unsigned prot = vp_prot(vp);
  const unsigned overlay = vp_overlay(vp);

  if (dfsc_is_translation(dfsc)) {  // translation fault at ANY level (Wine M1 fix 1a: was DFSC 0x07 only -- a
                                    // reservation with no L0-L2 tables yet faults at level 0-2 and is the same
                                    // AV/GUARD/RETRY question; which level the walk stopped at is irrelevant here)
    if (!vp_committed(vp)) {
      result = GMM_F_AV;  // still NOACCESS/reserved/decommitted now too: genuine
      goto out;
    }
    if (prot & GMM_PAGE_GUARD) {
      // Guard fires once: clear it, write valid PTE(s) for the underlying protection, invalid->valid (no TLBI).
      uint64_t page_ipa;
      if (r->type == GMM_TYPE_PRIVATE) {
        const uint64_t off = va - (r->base + cidx * 16384);
        page_ipa = r->chunks[cidx].ipa + off;
      } else {
        const size_t sidx = (r->view_off + (va - r->base)) / 16384;
        const uint64_t off = (r->view_off + (va - r->base)) - sidx * 16384;
        page_ipa = r->section->ipa[sidx] + off;
      }
      apply_page(g, r, va, idx, 0, 0, 0, prot & ~(unsigned)GMM_PAGE_GUARD, overlay, page_ipa);
      result = GMM_F_GUARD;
      goto out;
    }
    if (prot == GMM_PAGE_NOACCESS) {
      result = GMM_F_AV;
      goto out;
    }
    // Committed, not guard, not noaccess: the live descriptor must actually be valid now (encode() would return
    // a valid leaf) — this fault predates a fix another thread already applied. Nothing to do; just retry.
    result = GMM_F_RETRY;
    goto out;
  }

  if (dfsc_is_l3_permission(dfsc)) {  // permission fault: hardware saw a valid-but-forbidding descriptor
    if (!vp_committed(vp)) {
      result = GMM_F_BUG;  // a permission fault implies a valid descriptor, which implies committed
      goto out;
    }
    const int is_fetch = (ec == 0x20 || ec == 0x21);
    if (is_fetch) {
      // Wine M1 / D1 rule: PAGE_EXECUTE* pages are EL1-fetchable too (gmm_pte_encode), not only ARM64CODE ones.
      const unsigned exec_bits =
          GMM_PAGE_EXECUTE | GMM_PAGE_EXECUTE_READ | GMM_PAGE_EXECUTE_READWRITE | GMM_PAGE_EXECUTE_WRITECOPY;
      const int allowed = (prot & (GMM_PAGE_ARM64CODE | exec_bits)) != 0 && !(prot & GMM_PAGE_GUARD);
      result = allowed ? RETRY_STALE : GMM_F_AV;
      goto out;
    }
    const unsigned writable_bits = GMM_PAGE_READWRITE | GMM_PAGE_WRITECOPY | GMM_PAGE_EXECUTE_READWRITE |
                                    GMM_PAGE_EXECUTE_WRITECOPY;
    const int currently_writable = (prot & writable_bits) != 0 && !(overlay & (GMM_OVERLAY_WRITEWATCH | GMM_OVERLAY_SMC));
    if (wnr && !currently_writable) {
      const int underlying_writable = (prot & writable_bits) != 0;
      if (underlying_writable && (overlay & GMM_OVERLAY_SMC)) {
        // DESIGN NOTE (found during implementation): an SMC write is NOT self-resolving. gmm.h documents SMC as
        // "NOT one-shot; caller must gmm_set_overlay(clr=SMC) again" — meaning some higher layer (FEX's SMC
        // handling: I-cache maintenance, code-cache invalidation) must run BEFORE the access is allowed to
        // succeed. Returning GMM_F_RETRY_LOCAL_TLBI here (as this function's first draft did) would be a bug: it
        // tells the guest vector to just flush and retry, but the PTE and the overlay are both left unchanged
        // (still forced read-only), so the retry would fault identically — an infinite loop. Neither PTE nor
        // overlay are touched here; only gmm_set_overlay(..., clr=GMM_OVERLAY_SMC) (called by the exit handler,
        // after it has done whatever SMC handling it needs) performs the actual raise. GMM_F_GUARD is reused for
        // this "stop, an external actor must intervene before this becomes accessible again" signal, since the
        // enum (§1) has no dedicated SMC value and GUARD's arm/caller-driven-progress shape is the closest fit —
        // NOT because this is architecturally a guard page.
        result = GMM_F_GUARD;
        goto out;
      }
      if (underlying_writable && (overlay & GMM_OVERLAY_WRITEWATCH)) {
        // The raise moment: underlying protection allows writes, only the (one-shot) write-watch overlay was
        // forcing RO. Clear it now; the PTE becomes genuinely writable; a stale cached translation elsewhere
        // faults again and takes the "already fixed, local TLBI" path below.
        const unsigned new_overlay = overlay & ~(unsigned)GMM_OVERLAY_WRITEWATCH;
        uint64_t page_ipa;
        if (r->type == GMM_TYPE_PRIVATE) {
          const uint64_t off = va - (r->base + cidx * 16384);
          page_ipa = r->chunks[cidx].ipa + off;
        } else {
          const size_t sidx = (r->view_off + (va - r->base)) / 16384;
          const uint64_t off = (r->view_off + (va - r->base)) - sidx * 16384;
          page_ipa = r->section->ipa[sidx] + off;
        }
        apply_page(g, r, va, idx, 1, prot, overlay, prot, new_overlay, page_ipa);
        result = RETRY_STALE;  // eager: apply_page already shot the old RO entry down
        goto out;
      }
      result = GMM_F_AV;  // genuinely read-only (or NOACCESS-shaped) by vprot: real violation
      goto out;
    }
    if (!wnr && currently_writable) {
      // A read faulted with a permission DFSC even though vprot says this page is fully readable: only explained
      // by a stale stricter cached entry left over from an earlier raise on ANOTHER dimension (e.g. PXN clearing)
      // that also happened to touch AP — re-derive and let the guest local-TLBI.
      result = RETRY_STALE;
      goto out;
    }
    // The write is genuinely still forbidden by intended state, or some other combination this prototype's op
    // set cannot produce.
    result = currently_writable ? RETRY_STALE : GMM_F_AV;
    goto out;
  }

  result = GMM_F_BUG;  // unreachable: EC/DFSC were validated before the lock
out:
  pthread_mutex_unlock(&g->mtx);
  return result;
}

// ================================================================================================================
// gmm_walk: gmm_t-bound convenience wrapper around the oracle in gmm_walk.c.
int gmm_walk(const gmm_t *g, uint64_t va, gmm_xlat_t *out) {
  gmm_t *ncg = (gmm_t *)(uintptr_t)g;  // pt_reader/dealias take non-const; gmm_walk() itself does not mutate state
  va = dealias(ncg, va);
  gmm_walk_raw(g->root_ipa, g->cfg.t0sz, va, pt_reader, ncg, out);
  return 0;
}

// ================================================================================================================
// WINE M1 THIN API (gmm.h has the contract). Identity backing: host page == guest page, the CALLER owns the host
// mapping; gmm owns only stage 2 (chunk -> IPA) and stage 1 (descriptors). No region record, no Windows state.
static int s1_valid_arg(unsigned s1) {
  if (s1 & ~0xFu) return 0;
  if (!(s1 & GMM_S1_COMMIT) && (s1 & (GMM_S1_R | GMM_S1_W | GMM_S1_X))) return 0;
  return 1;
}
static int s1_is_valid_desc(unsigned s1) { return (s1 & GMM_S1_COMMIT) && (s1 & (GMM_S1_R | GMM_S1_W | GMM_S1_X)); }
// The ONE encoder: map the stage-1 state onto the PAGE_* value gmm_pte_encode() already implements (so the D1 PXN
// rule, AP, AF, SH, UXN are defined in exactly one place). W implies R; X implies R.
static uint64_t s1_encode(unsigned s1, uint64_t ipa) {
  if (!s1_is_valid_desc(s1))
    return (uint64_t)((s1 & GMM_S1_COMMIT) ? GMM_TAG_NOACCESS : GMM_TAG_RESERVED) << GMM_TAG_SHIFT;
  const int w = (s1 & GMM_S1_W) != 0, x = (s1 & GMM_S1_X) != 0;
  const unsigned prot = x ? (w ? GMM_PAGE_EXECUTE_READWRITE : GMM_PAGE_EXECUTE_READ)
                          : (w ? GMM_PAGE_READWRITE : GMM_PAGE_READONLY);
  return gmm_pte_encode(prot, 0, ipa);
}

typedef struct {
  uint64_t va;      // chunk VA
  tchunk_t *e;      // existing entry (stage-2 mapped) or NULL; re-resolved after the table may have grown
  uint8_t old_mask, new_mask;
  uint8_t need_map, mapped_now, need_unmap;
  uint64_t ipa;     // IPA the chunk will have (existing or newly mapped)
} tplan_t;

static int thin_overlap_forbidden(gmm_t *g, uint64_t va, uint64_t sz) {
  if (regions_overlap(g, va, sz)) return 1;
  if (g->cfg.alias_base) {
    const uint64_t lo = g->cfg.alias_base, hi = g->cfg.alias_base + 0x100000000ull;
    if (va < hi && lo < va + sz) return 1;
  }
  return 0;
}

// ================================================================================================================
// FAST MAPPING (2026-09-23): run records (gmm.h "run record"; DESIGN-guest-memory-manager.md "Fast mapping").
// Sorted by va; lookups are a binary search. Pointers into g->recs are invalidated by insert/remove, so callers
// hold VAs, not pointers, across mutations.
static size_t rec_upper(const gmm_t *g, uint64_t va) {  // first index with recs[i].va > va
  size_t lo = 0, hi = g->nrecs;
  while (lo < hi) {
    const size_t mid = (lo + hi) / 2;
    if (g->recs[mid].va <= va) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}
static s2rec_t *rec_find(gmm_t *g, uint64_t va) {
  const size_t i = rec_upper(g, va);
  if (!i) return NULL;
  s2rec_t *r = &g->recs[i - 1];
  return (va >= r->va && va < r->va + r->nchunks * 16384) ? r : NULL;
}
static int rec_reserve(gmm_t *g, size_t extra) {
  if (g->nrecs + extra <= g->caprecs) return 0;
  size_t nc = g->caprecs ? g->caprecs : 16;
  while (nc < g->nrecs + extra) nc *= 2;
  s2rec_t *n = realloc(g->recs, nc * sizeof(s2rec_t));
  if (!n) return -1;
  g->recs = n;
  g->caprecs = nc;
  return 0;
}
static void rec_insert(gmm_t *g, s2rec_t r) {  // capacity reserved by the caller
  const size_t i = rec_upper(g, r.va);
  memmove(&g->recs[i + 1], &g->recs[i], (g->nrecs - i) * sizeof(s2rec_t));
  g->recs[i] = r;
  g->nrecs++;
}
static void rec_remove(gmm_t *g, s2rec_t *r) {
  const size_t i = (size_t)(r - g->recs);
  memmove(&g->recs[i], &g->recs[i + 1], (g->nrecs - i - 1) * sizeof(s2rec_t));
  g->nrecs--;
}

// The caller-backing guard for a run: the host region containing va passes gmm_backing_check_caller's tests (tag
// 250, not file-backed, exactly READ|WRITE) and covers at least va's whole 16K page. Returns that region's end in
// *end (a run never extends past it: one backend->s2_map call never spans two VM map entries). 0 or -1.
static int caller_region_end(uint64_t va, uint64_t *end) {
  mach_vm_address_t addr = (mach_vm_address_t)va;
  mach_vm_size_t regsz = 0;
  vm_region_extended_info_data_t ext;
  mach_msg_type_number_t count = VM_REGION_EXTENDED_INFO_COUNT;
  mach_port_t obj = MACH_PORT_NULL;
  kern_return_t kr =
      mach_vm_region(mach_task_self(), &addr, &regsz, VM_REGION_EXTENDED_INFO, (vm_region_info_t)&ext, &count, &obj);
  if (obj != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), obj);
  if (kr != KERN_SUCCESS || addr > va || addr + regsz < va + 16384) return -1;
  if (ext.user_tag != GMM_VM_TAG || ext.external_pager != 0) return -1;
  if ((ext.protection & (VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE)) != (VM_PROT_READ | VM_PROT_WRITE)) return -1;
  *end = addr + regsz;
  return 0;
}
// Every 16K page of [va, va+sz) passes the caller guard (the range may span regions: used by PARANOID re-checks).
static int caller_range_ok(uint64_t va, uint64_t sz) {
  for (uint64_t p = va; p < va + sz; p += 16384)
    if (gmm_backing_check_caller(p, 16384) != 0) return 0;
  return 1;
}
static void paranoid_before_unmap(gmm_t *g, uint64_t va, uint64_t sz, uint64_t ipa) {
  if (!(g->cfg.flags & GMM_CFG_PARANOID) || caller_range_ok(va, sz)) return;
  // The caller changed its host mapping while this range was still stage-2 mapped: the ordering rule (gmm hook
  // first, host mapping change after) was broken. Stop with everything mapped.
  fprintf(stderr, "gmm: ORDERING VIOLATION: host range [0x%llx,+0x%llx) changed while stage-2 mapped (ipa=0x%llx) "
                  "-- aborting with it mapped\n", (unsigned long long)va, (unsigned long long)sz,
          (unsigned long long)ipa);
  abort();
}

typedef struct {
  size_t ci;     // first plan index
  uint64_t n;    // chunks
  uint64_t ipa;  // allocated IPA range (GMM_IPA_NONE until allocated)
  int mapped;
} tgroup_t;
typedef struct {
  uint64_t va, desc;  // a survivor descriptor saved across a whole-run remap
} tsaved_t;

// The one mutator behind gmm_vm_range_set/_pages/gmm_view_map/gmm_view_unmap. Caller holds g->mtx.
// s1arr (npages entries) or, if NULL, s1uni for every page.
//
// FAST MAPPING (2026-09-23): chunks gaining their first committed page are grouped into RUNS (VA-contiguous, one
// host region, at most cfg.s2_run_chunks), each mapped by ONE backend->s2_map of a contiguous IPA range. Chunks
// losing their last committed page are unmapped per run record: the whole record if every chunk of it is now
// empty (one exact unmap), else the emptied sub-ranges (split policy) or a whole-record unmap plus a re-map of the
// survivors at the same IPAs (GMM_CFG_S2_REMAP). With s2_run_chunks <= 1 every run and every record is one chunk,
// and the call sequence is exactly the Wine M1 one: one 16K s2_map per newly committed chunk, one 16K s2_unmap per
// emptied chunk.
static int thin_apply_locked(gmm_t *g, uint64_t va, size_t npages, const uint8_t *s1arr, unsigned s1uni,
                             int refuse_committed) {
  if (!npages || (va % 4096) != 0) return GMM_EINVAL;
  const uint64_t sz = (uint64_t)npages * 4096;
  const uint64_t va_limit = 1ull << (64 - g->cfg.t0sz);
  if (va + sz < va || va + sz > va_limit) return GMM_EINVAL;
  for (size_t i = 0; i < npages; i++)
    if (!s1_valid_arg(s1arr ? s1arr[i] : s1uni)) return GMM_EINVAL;
  const uint64_t c0 = va & ~16383ull;
  const size_t nchunks = (size_t)(((va + sz - 1) & ~16383ull) - c0) / 16384 + 1;
  // Checked on the 16K-rounded range: a stage-2 map covers the whole host page, so a thin range may not even share
  // a 16K chunk with a legacy region or the alias window.
  if (thin_overlap_forbidden(g, c0, (uint64_t)nchunks * 16384)) return GMM_EEXIST;
  const int remap_policy = (g->cfg.flags & GMM_CFG_S2_REMAP) != 0;
  const uint64_t cap = g->cfg.s2_run_chunks > 1 ? g->cfg.s2_run_chunks : 1;
  tplan_t *plan = calloc(nchunks, sizeof(tplan_t));
  tgroup_t *grp = calloc(nchunks, sizeof(tgroup_t));
  uint64_t *urec = calloc(nchunks, sizeof(uint64_t));  // VAs of the run records this call empties chunks of
  uint64_t *tlbi_va = NULL;
  tsaved_t *saved = NULL;
  size_t ngrp = 0, nurec = 0, nsaved = 0, nsaved_cap = 0;
  int rc = GMM_EINVAL;
  if (!plan || !grp || !urec) {
    rc = GMM_ENOMEM;
    goto out;
  }
  // ---- (A) plan + validate + reserve. Nothing observable changes in this phase. ----
  size_t need_map = 0;
  for (size_t ci = 0; ci < nchunks; ci++) {
    tplan_t *pl = &plan[ci];
    pl->va = c0 + ci * 16384;
    pl->e = tchunk_find(&g->thin, pl->va);
    pl->old_mask = pl->new_mask = pl->e ? pl->e->committed : 0;
    pl->ipa = pl->e ? pl->e->ipa : GMM_IPA_NONE;
  }
  for (size_t i = 0; i < npages; i++) {
    const uint64_t pva = va + i * 4096;
    const unsigned s1 = s1arr ? s1arr[i] : s1uni;
    tplan_t *pl = &plan[(pva - c0) / 16384];
    const uint8_t bit = (uint8_t)(1u << ((pva >> 12) & 3));
    if (refuse_committed && (pl->old_mask & bit)) {
      rc = GMM_EEXIST;
      goto out;
    }
    if (s1 & GMM_S1_COMMIT) pl->new_mask |= bit;
    else pl->new_mask &= (uint8_t)~bit;
  }
  for (size_t ci = 0; ci < nchunks; ci++) {
    tplan_t *pl = &plan[ci];
    pl->need_map = pl->new_mask && !pl->e;
    pl->need_unmap = !pl->new_mask && pl->e;
    need_map += pl->need_map;
  }
  if (ipa_available(g) < need_map) {
    rc = GMM_ENOIPA;
    goto out;
  }
  for (size_t i = 0; i < npages; i++) {  // tables for every descriptor that will be valid (one lookup per 2 MiB)
    const uint64_t pva = va + i * 4096;
    if (!s1_is_valid_desc(s1arr ? s1arr[i] : s1uni)) continue;
    if (pt_lookup_slot(g, pva)) continue;
    if ((rc = pt_ensure(g, pva)) != 0) goto out;
  }
  // Runs: maximal stretches of chunks gaining their first committed page, cut at the cap and at the end of the host
  // region the run starts in (the backing guard, checked once per region instead of once per chunk).
  for (size_t ci = 0; ci < nchunks; ci++) {
    if (!plan[ci].need_map) continue;
    uint64_t rend = 0;
    if (caller_region_end(plan[ci].va, &rend) != 0) {
      rc = GMM_EGUARD;
      goto out;
    }
    uint64_t n = 1;
    while (ci + n < nchunks && plan[ci + n].need_map && n < cap && plan[ci + n].va + 16384 <= rend) n++;
    grp[ngrp++] = (tgroup_t){.ci = ci, .n = n, .ipa = GMM_IPA_NONE};
    ci += n - 1;
  }
  // A contiguous IPA range per run. If the free space is fragmented, a run is split in halves until each piece
  // finds one (so only a genuine shortage -- already excluded above -- could fail; the loop keeps that honest).
  for (size_t gi = 0; gi < ngrp; gi++) {
    uint64_t ipa;
    while ((ipa = alloc_ipa_range(g, grp[gi].n)) == GMM_IPA_NONE && grp[gi].n > 1) {
      const uint64_t half = grp[gi].n / 2;
      memmove(&grp[gi + 2], &grp[gi + 1], (ngrp - gi - 1) * sizeof(tgroup_t));
      grp[gi + 1] = (tgroup_t){.ci = grp[gi].ci + half, .n = grp[gi].n - half, .ipa = GMM_IPA_NONE};
      grp[gi].n = half;
      ngrp++;
    }
    if (ipa == GMM_IPA_NONE) {
      for (size_t gj = 0; gj < gi; gj++) free_ipa_range(g, grp[gj].ipa, grp[gj].n);  // never mapped: safe
      rc = GMM_ENOIPA;
      goto out;
    }
    grp[gi].ipa = ipa;
  }
  // The run records this call will empty chunks of (plan and records are both VA-ordered: dedupe consecutively).
  for (size_t ci = 0; ci < nchunks; ci++) {
    if (!plan[ci].need_unmap) continue;
    const s2rec_t *r = rec_find(g, plan[ci].va);
    if (!r) {
      fprintf(stderr, "gmm: BUG: mapped chunk 0x%llx has no run record -- aborting\n", (unsigned long long)plan[ci].va);
      abort();
    }
    if (!nurec || urec[nurec - 1] != r->va) urec[nurec++] = r->va;
  }
  // Remap policy: a record keeping some chunks will have its survivors' descriptors saved, invalidated and
  // restored around a whole-record unmap + re-map. Count them (upper bound: 4 per surviving chunk) and re-run the
  // backing guard on every survivor piece now, so a failure is a clean GMM_EGUARD before anything changes.
  if (remap_policy) {
    for (size_t k = 0; k < nurec; k++) {
      const s2rec_t *r = rec_find(g, urec[k]);
      uint64_t surv = 0;
      for (uint64_t c = 0; c < r->nchunks; c++) {
        const uint64_t cva = r->va + c * 16384;
        const tplan_t *pl = (cva >= c0 && cva < c0 + (uint64_t)nchunks * 16384) ? &plan[(cva - c0) / 16384] : NULL;
        const tchunk_t *e = tchunk_find(&g->thin, cva);
        const uint8_t mask = pl ? pl->new_mask : e->committed;
        if (mask) {
          surv++;
          if (!caller_range_ok(cva, 16384)) {
            rc = GMM_EGUARD;
            for (size_t gj = 0; gj < ngrp; gj++) free_ipa_range(g, grp[gj].ipa, grp[gj].n);
            goto out;
          }
        }
      }
      nsaved_cap += 4 * surv;
    }
  }
  tlbi_va = malloc((npages + nsaved_cap + 1) * sizeof(uint64_t));
  saved = malloc((nsaved_cap + 1) * sizeof(tsaved_t));
  if (!tlbi_va || !saved || tchunk_reserve(&g->thin, need_map) != 0 ||
      rec_reserve(g, ngrp + 2 * nchunks + 2 * nurec + 2) != 0) {
    for (size_t gj = 0; gj < ngrp; gj++) free_ipa_range(g, grp[gj].ipa, grp[gj].n);
    rc = GMM_ENOMEM;
    goto out;
  }
  for (size_t ci = 0; ci < nchunks; ci++)  // the reserve may have rehashed: re-resolve existing entries
    if (plan[ci].e) plan[ci].e = tchunk_find(&g->thin, plan[ci].va);

  // ---- (B) stage-2 map every run. All-or-nothing. ----
  for (size_t gi = 0; gi < ngrp; gi++) {
    tgroup_t *gr = &grp[gi];
    const uint64_t gva = plan[gr->ci].va;
    const uint32_t sr = g->backend.s2_map((void *)(uintptr_t)gva, gr->ipa, gr->n * 16384, GMM_S2_RWX);
    if (sr != 0) {
      // No descriptor references any IPA this call mapped yet, so no TLBI is needed to take them back: undo every
      // earlier run of this call with its own EXACT unmap. The failed run's IPA range is quarantined (never
      // freed): the map may be partly in place. The ranges of runs not yet attempted were never mapped: freed.
      // The host memory is the caller's.
      fprintf(stderr, "gmm: thin s2_map(va=0x%llx, ipa=0x%llx, %llu KiB) failed 0x%x -- rolling back, IPA quarantined\n",
              (unsigned long long)gva, (unsigned long long)gr->ipa, (unsigned long long)(gr->n * 16), sr);
      for (size_t gj = 0; gj < gi; gj++) {
        if (g->backend.s2_unmap(grp[gj].ipa, grp[gj].n * 16384) != 0) {
          fprintf(stderr, "gmm: rollback s2_unmap(ipa=0x%llx) FAILED -- aborting with it mapped\n",
                  (unsigned long long)grp[gj].ipa);
          abort();
        }
        trace_push_sz(g, GMM_EV_S2_UNMAP, plan[grp[gj].ci].va, grp[gj].ipa, grp[gj].n * 16384);
        free_ipa_range(g, grp[gj].ipa, grp[gj].n);
      }
      for (size_t gj = gi + 1; gj < ngrp; gj++) free_ipa_range(g, grp[gj].ipa, grp[gj].n);
      rc = GMM_ES2;
      goto out;
    }
    trace_push_sz(g, GMM_EV_S2_MAP, gva, gr->ipa, gr->n * 16384);
    gr->mapped = 1;
  }
  for (size_t gi = 0; gi < ngrp; gi++) {
    const tgroup_t *gr = &grp[gi];
    for (uint64_t k = 0; k < gr->n; k++) {
      tplan_t *pl = &plan[gr->ci + k];
      pl->ipa = gr->ipa + k * 16384;
      pl->mapped_now = 1;
      pl->e = tchunk_insert(&g->thin, pl->va, pl->ipa);
    }
    rec_insert(g, (s2rec_t){.va = plan[gr->ci].va, .ipa = gr->ipa, .nchunks = gr->n, .whole = 1});
    g->st.map_calls++;
    g->st.map_bytes += gr->n * 16384;
  }
  // (insert never rehashes -- reserved above -- so every plan[].e stays valid from here on)

  // ---- (C) descriptors. Nothing below can fail. ----
  size_t ntlbi = 0;
  for (size_t i = 0; i < npages; i++) {
    const uint64_t pva = va + i * 4096;
    const unsigned s1 = s1arr ? s1arr[i] : s1uni;
    const tplan_t *pl = &plan[(pva - c0) / 16384];
    const uint64_t new_desc = s1_encode(s1, (pl->ipa == GMM_IPA_NONE ? 0 : pl->ipa) + (pva - pl->va));
    uint64_t *slot = pt_lookup_slot(g, pva);
    const uint64_t old_desc = slot ? *slot : 0;
    if (old_desc == new_desc) continue;
    if (!slot) {
      if (!(new_desc & 1ull)) continue;  // already a translation fault at a higher level: nothing to write
      fprintf(stderr, "gmm: BUG: no table for va=0x%llx after pt_ensure -- aborting\n", (unsigned long long)pva);
      abort();
    }
    __atomic_store_n(slot, new_desc, __ATOMIC_RELEASE);
    trace_push(g, (new_desc & 1ull) ? GMM_EV_PTE_VALID : GMM_EV_PTE_INVALID, pva, leaf_trace_ipa(new_desc));
    if (valid_change_needs_tlbi(g, old_desc, new_desc)) tlbi_va[ntlbi++] = pva;
  }
  for (size_t ci = 0; ci < nchunks; ci++)
    if (plan[ci].e) plan[ci].e->committed = plan[ci].new_mask;
  // (C') remap policy: every still-valid descriptor of a survivor of a record losing chunks goes invalid too, and
  // is shot down with the rest; it is restored after its chunk is stage-2 mapped again (E).
  if (remap_policy) {
    for (size_t k = 0; k < nurec; k++) {
      const s2rec_t *r = rec_find(g, urec[k]);
      int any_empty_left = 0, any_survivor = 0;
      for (uint64_t c = 0; c < r->nchunks; c++) {
        if (tchunk_find(&g->thin, r->va + c * 16384)->committed) any_survivor = 1;
        else any_empty_left = 1;
      }
      if (!any_survivor || !any_empty_left) continue;  // wholly emptied (exact unmap), or nothing to do
      for (uint64_t c = 0; c < r->nchunks; c++) {
        const uint64_t cva = r->va + c * 16384;
        if (!tchunk_find(&g->thin, cva)->committed) continue;
        for (int p = 0; p < 4; p++) {
          const uint64_t pva = cva + (uint64_t)p * 4096;
          uint64_t *slot = pt_lookup_slot(g, pva);
          if (!slot || !(*slot & 1ull)) continue;
          saved[nsaved++] = (tsaved_t){pva, *slot};
          const uint64_t inv = (uint64_t)GMM_TAG_NOACCESS << GMM_TAG_SHIFT;
          __atomic_store_n(slot, inv, __ATOMIC_RELEASE);
          trace_push(g, GMM_EV_PTE_INVALID, pva, GMM_TAG_NOACCESS);
          tlbi_va[ntlbi++] = pva;
        }
      }
    }
  }

  // ---- (D) one batched shootdown for every descriptor that was valid and changed ----
  if (ntlbi) do_tlbi(g, tlbi_va, ntlbi);

  // ---- (E) stage-2 unmap what no committed page needs any more; free each IPA only after its unmap returned ----
  for (size_t k = 0; k < nurec; k++) {
    s2rec_t *r = rec_find(g, urec[k]);
    int any_survivor = 0;
    for (uint64_t c = 0; c < r->nchunks; c++) any_survivor |= tchunk_find(&g->thin, r->va + c * 16384)->committed != 0;
    if (!any_survivor) {
      // Every chunk of the record is empty (retained ones included): unmap the whole record. If it is exactly one
      // map call's range this is the shape proven live since G5a, and a failure is a broken invariant (abort, as
      // before). If it is a piece left by a split, it is a sub-range unmap: refused -> retained, like below.
      const uint64_t rva = r->va, ripa = r->ipa, rn = r->nchunks;
      if (!r->whole && g->st.split_refused) continue;  // never attempt a sub-range unmap again: stays retained
      paranoid_before_unmap(g, rva, rn * 16384, ripa);
      const uint32_t ur = g->backend.s2_unmap(ripa, rn * 16384);
      if (ur != 0) {
        if (r->whole) {
          fprintf(stderr, "gmm: thin s2_unmap(ipa=0x%llx, %llu KiB) FAILED 0x%x -- aborting with it left mapped\n",
                  (unsigned long long)ripa, (unsigned long long)(rn * 16), ur);
          abort();
        }
        fprintf(stderr, "gmm: backend refused sub-range s2_unmap(ipa=0x%llx, %llu KiB) 0x%x -- chunks retained, "
                        "no further sub-range unmap will be attempted\n",
                (unsigned long long)ripa, (unsigned long long)(rn * 16), ur);
        g->st.unmap_refused++;
        g->st.split_refused = 1;
        continue;
      }
      trace_push_sz(g, GMM_EV_S2_UNMAP, rva, ripa, rn * 16384);
      g->st.unmap_calls++;
      if (r->whole) g->st.unmap_exact++;
      else g->st.unmap_sub++;
      rec_remove(g, r);
      for (uint64_t c = 0; c < rn; c++) tchunk_remove(&g->thin, tchunk_find(&g->thin, rva + c * 16384));
      free_ipa_range(g, ripa, rn);
      continue;
    }
    if (remap_policy) {
      // Whole-record unmap (exact: remap-policy records are always whole), then one map per surviving piece at
      // the SAME IPAs, then restore the survivors' saved descriptors (invalid->valid: no TLBI). Every survivor
      // descriptor is invalid and shot down (C'/D), so nothing can reach the record's IPAs in between.
      const s2rec_t old = *r;
      paranoid_before_unmap(g, old.va, old.nchunks * 16384, old.ipa);
      if (g->backend.s2_unmap(old.ipa, old.nchunks * 16384) != 0) {
        fprintf(stderr, "gmm: remap: whole-run s2_unmap(ipa=0x%llx) FAILED -- aborting with it left mapped\n",
                (unsigned long long)old.ipa);
        abort();
      }
      trace_push_sz(g, GMM_EV_S2_UNMAP, old.va, old.ipa, old.nchunks * 16384);
      g->st.unmap_calls++;
      g->st.unmap_exact++;
      g->st.remaps++;
      rec_remove(g, r);
      for (uint64_t c = 0; c < old.nchunks;) {
        const uint64_t cva = old.va + c * 16384;
        if (!tchunk_find(&g->thin, cva)->committed) {  // emptied: forget it, free its IPA (the unmap returned)
          tchunk_remove(&g->thin, tchunk_find(&g->thin, cva));
          free_ipa(g, old.ipa + c * 16384);
          c++;
          continue;
        }
        uint64_t n = 1;
        while (c + n < old.nchunks && tchunk_find(&g->thin, old.va + (c + n) * 16384)->committed) n++;
        const uint64_t pipa = old.ipa + c * 16384;
        if (!caller_range_ok(cva, n * 16384) ||  // re-checked right before the map (was checked in A)
            g->backend.s2_map((void *)(uintptr_t)cva, pipa, n * 16384, GMM_S2_RWX) != 0) {
          fprintf(stderr, "gmm: remap: s2_map(va=0x%llx, ipa=0x%llx) of a survivor FAILED -- aborting (its "
                          "descriptors are invalid, nothing references the unmapped IPAs)\n",
                  (unsigned long long)cva, (unsigned long long)pipa);
          abort();
        }
        trace_push_sz(g, GMM_EV_S2_MAP, cva, pipa, n * 16384);
        g->st.map_calls++;
        g->st.map_bytes += n * 16384;
        rec_insert(g, (s2rec_t){.va = cva, .ipa = pipa, .nchunks = n, .whole = 1});
        c += n;
      }
      for (size_t i = 0; i < nsaved; i++) {
        if (saved[i].va < old.va || saved[i].va >= old.va + old.nchunks * 16384) continue;
        __atomic_store_n(pt_lookup_slot(g, saved[i].va), saved[i].desc, __ATOMIC_RELEASE);
        trace_push(g, GMM_EV_PTE_VALID, saved[i].va, leaf_trace_ipa(saved[i].desc));
      }
      continue;
    }
    // Split policy: one sub-range unmap per maximal stretch of empty chunks; the record splits around each hole.
    if (g->st.split_refused) continue;  // retained (see GMM_CFG_S2_REMAP in gmm.h)
    uint64_t rva = r->va;
    for (;;) {
      r = rec_find(g, rva);
      uint64_t a = 0;
      while (a < r->nchunks && tchunk_find(&g->thin, r->va + a * 16384)->committed) a++;
      if (a == r->nchunks) break;  // no empty chunk left in this (right-hand) piece
      uint64_t b = a;
      while (b < r->nchunks && !tchunk_find(&g->thin, r->va + b * 16384)->committed) b++;
      const uint64_t hva = r->va + a * 16384, hipa = r->ipa + a * 16384, hn = b - a;
      paranoid_before_unmap(g, hva, hn * 16384, hipa);
      const uint32_t ur = g->backend.s2_unmap(hipa, hn * 16384);
      if (ur != 0) {
        fprintf(stderr, "gmm: backend refused sub-range s2_unmap(ipa=0x%llx, %llu KiB) 0x%x -- chunks retained, "
                        "no further sub-range unmap will be attempted\n",
                (unsigned long long)hipa, (unsigned long long)(hn * 16), ur);
        g->st.unmap_refused++;
        g->st.split_refused = 1;
        break;
      }
      trace_push_sz(g, GMM_EV_S2_UNMAP, hva, hipa, hn * 16384);
      g->st.unmap_calls++;
      g->st.unmap_sub++;
      const s2rec_t old = *r;
      rec_remove(g, r);
      if (a) rec_insert(g, (s2rec_t){.va = old.va, .ipa = old.ipa, .nchunks = a, .whole = 0});
      if (b < old.nchunks)
        rec_insert(g, (s2rec_t){.va = old.va + b * 16384, .ipa = old.ipa + b * 16384, .nchunks = old.nchunks - b,
                                .whole = 0});
      for (uint64_t c = a; c < b; c++) tchunk_remove(&g->thin, tchunk_find(&g->thin, old.va + c * 16384));
      free_ipa_range(g, hipa, hn);
      if (b >= old.nchunks) break;
      rva = old.va + b * 16384;
    }
  }
  rc = 0;
out:
  free(plan);
  free(grp);
  free(urec);
  free(tlbi_va);
  free(saved);
  return rc;
}

int gmm_vm_range_set(gmm_t *g, uint64_t va, size_t size, unsigned s1) {
  if (!size || (size % 4096) != 0) return GMM_EINVAL;
  pthread_mutex_lock(&g->mtx);
  const int rc = thin_apply_locked(g, va, size / 4096, NULL, s1, 0);
  pthread_mutex_unlock(&g->mtx);
  return rc;
}
int gmm_vm_range_set_pages(gmm_t *g, uint64_t va, size_t npages, const uint8_t *s1) {
  if (!s1) return GMM_EINVAL;
  pthread_mutex_lock(&g->mtx);
  const int rc = thin_apply_locked(g, va, npages, s1, 0, 0);
  pthread_mutex_unlock(&g->mtx);
  return rc;
}
int gmm_view_map(gmm_t *g, uint64_t va, size_t size, const void *host_backing, unsigned s1) {
  if (!size || (size % 4096) != 0 || host_backing != (const void *)(uintptr_t)va) return GMM_EINVAL;
  pthread_mutex_lock(&g->mtx);
  const int rc = thin_apply_locked(g, va, size / 4096, NULL, s1, 1);
  pthread_mutex_unlock(&g->mtx);
  return rc;
}
int gmm_view_unmap(gmm_t *g, uint64_t va, size_t size) {
  if (!size || (size % 4096) != 0) return GMM_EINVAL;
  pthread_mutex_lock(&g->mtx);
  const int rc = thin_apply_locked(g, va, size / 4096, NULL, GMM_S1_NONE, 0);
  pthread_mutex_unlock(&g->mtx);
  return rc;
}
int gmm_vm_s2_mapped(gmm_t *g, uint64_t va) {
  pthread_mutex_lock(&g->mtx);
  const int r = tchunk_find(&g->thin, va & ~16383ull) != NULL;
  pthread_mutex_unlock(&g->mtx);
  return r;
}
void *gmm_vm_host_ptr(gmm_t *g, uint64_t va) {
  pthread_mutex_lock(&g->mtx);
  const tchunk_t *c = tchunk_find(&g->thin, va & ~16383ull);
  void *p = (c && (c->committed & (1u << ((va >> 12) & 3)))) ? (void *)(uintptr_t)va : NULL;
  pthread_mutex_unlock(&g->mtx);
  return p;
}

gmm_vfault_t gmm_vm_fault(gmm_t *g, uint64_t far, uint64_t esr) {
  if (!esr_is_memory_abort(esr) || (esr & (1ull << 10))) return GMM_VF_FATAL;
  const unsigned ec = (unsigned)(esr >> 26), dfsc = (unsigned)(esr & 0x3F);
  if (dfsc == 0x21) return GMM_VF_WINE;  // alignment fault: the application's (STATUS_DATATYPE_MISALIGNMENT)
  if (!dfsc_is_translation(dfsc) && !dfsc_is_l3_permission(dfsc)) return GMM_VF_FATAL;
  // gmm descriptors give EL0 nothing (AP[1]=0, UXN=1): an abort from a lower EL is never a stale-permission race.
  if (ec == 0x20 || ec == 0x24) return GMM_VF_WINE;
  pthread_mutex_lock(&g->mtx);  // serialise against a range_set on another thread (its TLBI then precedes us)
  gmm_xlat_t x;
  gmm_walk(g, far, &x);
  gmm_vfault_t r = GMM_VF_WINE;
  if (x.valid) {
    const int is_fetch = (ec == 0x21), is_write = !is_fetch && ((esr >> 6) & 1);
    const int permitted = is_fetch ? !x.pxn : (is_write ? !x.ap_ro : 1);
    r = permitted ? GMM_VF_RETRY : GMM_VF_WINE;
  }
  pthread_mutex_unlock(&g->mtx);
  return r;
}

// ================================================================================================================
// FAST MAPPING (2026-09-23): run-record queries, stats, and the TEST SUPPORT consistency check (gmm.h).
int gmm_vm_s2_run(gmm_t *g, uint64_t va, uint64_t *run_va, uint64_t *run_ipa, uint64_t *run_bytes) {
  pthread_mutex_lock(&g->mtx);
  const s2rec_t *r = rec_find(g, va);
  if (r) {
    if (run_va) *run_va = r->va;
    if (run_ipa) *run_ipa = r->ipa;
    if (run_bytes) *run_bytes = r->nchunks * 16384;
  }
  pthread_mutex_unlock(&g->mtx);
  return r != NULL;
}
void gmm_vm_s2_stats(gmm_t *g, gmm_s2_stats_t *out) {
  pthread_mutex_lock(&g->mtx);
  *out = g->st;
  out->records = g->nrecs;
  out->mapped_chunks = g->thin.n;
  out->retained_chunks = 0;
  for (size_t i = 0; i < g->thin.cap; i++)
    if (g->thin.slots[i].key && !g->thin.slots[i].committed) out->retained_chunks++;
  pthread_mutex_unlock(&g->mtx);
}
uint64_t gmm_vm_chunk_ipa(gmm_t *g, uint64_t va) {
  pthread_mutex_lock(&g->mtx);
  const tchunk_t *c = tchunk_find(&g->thin, va & ~16383ull);
  const uint64_t ipa = c ? c->ipa : UINT64_MAX;
  pthread_mutex_unlock(&g->mtx);
  return ipa;
}
uint64_t gmm_debug_ipa_available(gmm_t *g) {
  pthread_mutex_lock(&g->mtx);
  const uint64_t n = ipa_available(g);
  pthread_mutex_unlock(&g->mtx);
  return n;
}
static int ipa_in_free(const gmm_t *g, uint64_t ipa) {
  if (ipa >= g->ipa_bump && ipa < g->cfg.ipa_hi) return 1;
  for (size_t i = 0; i < g->nifree; i++)
    if (ipa >= g->ifree[i].lo && ipa < g->ifree[i].hi) return 1;
  return 0;
}
static int cmp_rec_ipa(const void *a, const void *b) {
  const s2rec_t *x = a, *y = b;
  return x->ipa < y->ipa ? -1 : x->ipa > y->ipa;
}
int gmm_debug_check(gmm_t *g) {
  int bad = 0;
#define DBAD(...) (bad++, fprintf(stderr, "gmm_debug_check: " __VA_ARGS__), fputc('\n', stderr))
  pthread_mutex_lock(&g->mtx);
  // free list: sorted, coalesced, aligned, inside [ipa_lo, bump), never touching the bump (it would have folded)
  for (size_t i = 0; i < g->nifree; i++) {
    const ipa_ext_t *e = &g->ifree[i];
    if (e->lo >= e->hi || (e->lo | e->hi) % 16384 || e->lo < g->cfg.ipa_lo || e->hi >= g->ipa_bump)
      DBAD("free extent %zu [0x%llx,0x%llx) malformed (bump 0x%llx)", i, (unsigned long long)e->lo,
           (unsigned long long)e->hi, (unsigned long long)g->ipa_bump);
    if (i + 1 < g->nifree && e->hi >= g->ifree[i + 1].lo) DBAD("free extents %zu/%zu not sorted+coalesced", i, i + 1);
  }
  // records: sorted, disjoint in VA, every chunk present with the record's IPA arithmetic, never in the free list
  uint64_t rec_chunks = 0;
  for (size_t i = 0; i < g->nrecs; i++) {
    const s2rec_t *r = &g->recs[i];
    if (!r->nchunks || r->va % 16384 || r->ipa % 16384) DBAD("record %zu malformed", i);
    if (i + 1 < g->nrecs && r->va + r->nchunks * 16384 > g->recs[i + 1].va) DBAD("records %zu/%zu overlap in VA", i, i + 1);
    rec_chunks += r->nchunks;
    for (uint64_t c = 0; c < r->nchunks; c++) {
      const tchunk_t *t = tchunk_find(&g->thin, r->va + c * 16384);
      if (!t) {
        DBAD("record %zu (va 0x%llx) has a hole at chunk %llu", i, (unsigned long long)r->va, (unsigned long long)c);
        continue;
      }
      if (t->ipa != r->ipa + c * 16384)
        DBAD("chunk 0x%llx ipa 0x%llx != record arithmetic 0x%llx", (unsigned long long)(r->va + c * 16384),
             (unsigned long long)t->ipa, (unsigned long long)(r->ipa + c * 16384));
      if (ipa_in_free(g, t->ipa)) DBAD("mapped chunk IPA 0x%llx is also FREE", (unsigned long long)t->ipa);
      // descriptors of its 4 pages: valid => committed and pointing at the chunk's IPA + offset
      for (int p = 0; p < 4; p++) {
        const uint64_t pva = r->va + c * 16384 + (uint64_t)p * 4096;
        uint64_t *slot = pt_lookup_slot(g, pva);
        const uint64_t d = slot ? *slot : 0;
        if (!(d & 1ull)) continue;
        if (!(t->committed & (1u << p))) DBAD("va 0x%llx valid but not committed", (unsigned long long)pva);
        if ((d & 0x0000fffffffff000ull) != t->ipa + (uint64_t)p * 4096)
          DBAD("va 0x%llx descriptor ipa 0x%llx != 0x%llx", (unsigned long long)pva,
               (unsigned long long)(d & 0x0000fffffffff000ull), (unsigned long long)(t->ipa + (uint64_t)p * 4096));
      }
    }
  }
  if (rec_chunks != g->thin.n)
    DBAD("records cover %llu chunks, chunk table has %zu", (unsigned long long)rec_chunks, g->thin.n);
  if (g->nrecs) {  // disjoint in IPA
    s2rec_t *by_ipa = malloc(g->nrecs * sizeof(s2rec_t));
    if (by_ipa) {
      memcpy(by_ipa, g->recs, g->nrecs * sizeof(s2rec_t));
      qsort(by_ipa, g->nrecs, sizeof(s2rec_t), cmp_rec_ipa);
      for (size_t i = 0; i + 1 < g->nrecs; i++)
        if (by_ipa[i].ipa + by_ipa[i].nchunks * 16384 > by_ipa[i + 1].ipa)
          DBAD("records overlap in IPA at 0x%llx", (unsigned long long)by_ipa[i + 1].ipa);
      free(by_ipa);
    }
  }
  // legacy chunks and section chunks: never in the free list
  for (size_t i = 0; i < g->nregions; i++) {
    const gmm_region_t *r = &g->regions[i];
    if (r->chunks)
      for (size_t c = 0; c < r->size / 16384; c++)
        if (r->chunks[c].s2_mapped && ipa_in_free(g, r->chunks[c].ipa))
          DBAD("legacy chunk IPA 0x%llx is also FREE", (unsigned long long)r->chunks[c].ipa);
    if (r->section)
      for (size_t c = 0; c < r->section->nchunks; c++)
        if (ipa_in_free(g, r->section->ipa[c]))
          DBAD("section chunk IPA 0x%llx is also FREE", (unsigned long long)r->section->ipa[c]);
  }
  pthread_mutex_unlock(&g->mtx);
#undef DBAD
  return bad;
}
