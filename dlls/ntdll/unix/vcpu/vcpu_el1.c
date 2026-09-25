/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 the openrosetta / fex_macos contributors. See vcpu_el1.h for the full MIT text and the
 * decisions [Dn] referenced below.
 *
 * NO hv_* SYMBOL IS REFERENCED IN THIS FILE [D1]. Hypervisor.framework headers are included for constants and the
 * hv_vcpu_exit_t layout only; every call goes through vel1_hv_ops.
 */
#include "vcpu_el1.h"

#include <Hypervisor/Hypervisor.h>
#include <libkern/OSCacheControl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/semaphore.h>
#include <string.h>

/* ================================================================================================ blob [D5] */
size_t vel1_blob_size(void) { return (size_t)(vel1_blob_end - vel1_blob_start); }

/* The destination must not be executable host memory: the library's own __TEXT copy, MAP_JIT memory, or any other
   executable mapping. Those are the memory classes whose stage-2 mapping panicked the machine (2026-09-21). */
static bool host_range_is_executable(const void* p, size_t n) {
  mach_vm_address_t a = (mach_vm_address_t)(uintptr_t)p;
  const mach_vm_address_t end = a + n;
  while (a < end) {
    mach_vm_address_t r = a;
    mach_vm_size_t sz = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;
    if (mach_vm_region(mach_task_self(), &r, &sz, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &cnt, &obj) !=
        KERN_SUCCESS) {
      return true; /* unknown: refuse */
    }
    if (r > a) return true; /* a hole: not memory we can vouch for */
    if (info.protection & VM_PROT_EXECUTE) return true;
    if (!(info.protection & VM_PROT_WRITE)) return true;
    a = r + sz;
  }
  return false;
}

int vel1_blob_install(void* dst, size_t dst_size) {
  const size_t n = vel1_blob_size();
  if (!dst || dst_size < VEL1_BLOB_PAGE || ((uintptr_t)dst & (VEL1_BLOB_PAGE - 1)) || n > VEL1_BLOB_PAGE) {
    return VEL1_E_ARG;
  }
  if (host_range_is_executable(dst, VEL1_BLOB_PAGE)) return VEL1_E_EXEC_MEMORY;
  memcpy(dst, vel1_blob_start, n);
  memset((uint8_t*)dst + n, 0, VEL1_BLOB_PAGE - n); /* zero = udf #0 */
  sys_icache_invalidate(dst, VEL1_BLOB_PAGE);
  return VEL1_OK;
}

/* ========================================================================================== VM + kicker [D2][D8] */
static pthread_mutex_t g_vm_mu = PTHREAD_MUTEX_INITIALIZER;
static bool g_vm_created;
static const vel1_hv_ops* g_vm_ops;
static uint32_t g_vm_tcr_ips;
static _Atomic int g_live_vcpus;

static pthread_mutex_t g_reg_mu = PTHREAD_MUTEX_INITIALIZER; /* lock order: g_reg_mu -> v->life_lock */
static vel1_vcpu* g_reg[VEL1_MAX_VCPUS];
static semaphore_t g_ksem = MACH_PORT_NULL; /* written before any vCPU exists; read by handlers */
static pthread_t g_kthread;
static _Atomic int g_kstop;

static void* kicker_main(void* arg) {
  (void)arg;
  pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
  for (;;) {
    const kern_return_t kr = semaphore_wait(g_ksem);
    if (kr != KERN_SUCCESS && kr != KERN_ABORTED) break;
    if (atomic_load(&g_kstop)) break;
    pthread_mutex_lock(&g_reg_mu);
    for (unsigned i = 0; i < VEL1_MAX_VCPUS; ++i) {
      vel1_vcpu* v = g_reg[i];
      if (!v || !atomic_exchange(&v->kick_req, 0)) continue;
      os_unfair_lock_lock(&v->life_lock); /* vk:1366: lock + live bracket every cross-thread hv_vcpus_exit */
      if (atomic_load(&v->live) && atomic_load(&v->in_run)) {
        uint64_t id = v->id; /* hv_vcpus_exit takes an array (vk:1369) */
        if (v->ops->vcpus_exit(&id, 1) == 0) atomic_fetch_add_explicit(&v->kicker_exits, 1, memory_order_relaxed);
      }
      os_unfair_lock_unlock(&v->life_lock);
    }
    pthread_mutex_unlock(&g_reg_mu);
  }
  return NULL;
}

int vel1_ips_for_ipa_bits(uint32_t bits) {
  switch (bits) {
  case 32: return 0;
  case 36: return 1;
  case 40: return 2;
  case 42: return 3;
  case 44: return 4;
  case 48: return 5;
  case 52: return 6;
  default: return -1;
  }
}

int vel1_vm_create(const vel1_hv_ops* ops, uint32_t ipa_bits, vel1_vm_info* info) {
  vel1_vm_info local;
  if (!info) info = &local;
  memset(info, 0, sizeof *info);
  if (!ops) return VEL1_E_ARG;
  int ips = VEL1_TCR_IPS_PROVEN;
  if (ipa_bits) {
    ips = vel1_ips_for_ipa_bits(ipa_bits);
    if (ips < 0) return VEL1_E_ARG;
  }
  pthread_mutex_lock(&g_vm_mu);
  int rc = VEL1_OK;
  int32_t r;
  if (g_vm_created) {
    rc = VEL1_E_STATE;
    goto out;
  }
  r = ops->vm_get_max_ipa(&info->max_ipa_bits); /* proven query (hvf_proto.c:359) */
  if (r == 0 && ipa_bits) r = ops->vm_get_default_ipa(&info->default_ipa_bits); /* new: only with a requested size */
  if (r) {
    info->hv_err = r;
    rc = VEL1_E_HV;
    goto out;
  }
  if (ipa_bits > info->max_ipa_bits) {
    rc = VEL1_E_IPA_TOO_BIG;
    goto out;
  }
  if (semaphore_create(mach_task_self(), &g_ksem, SYNC_POLICY_FIFO, 0) != KERN_SUCCESS) {
    g_ksem = MACH_PORT_NULL;
    rc = VEL1_E_NO_KICKER;
    goto out;
  }
  r = ops->vm_create(ipa_bits);
  if (r) {
    semaphore_destroy(mach_task_self(), g_ksem);
    g_ksem = MACH_PORT_NULL;
    info->hv_err = r;
    rc = VEL1_E_HV;
    goto out;
  }
  g_vm_ops = ops;
  atomic_store(&g_kstop, 0);
  if (pthread_create(&g_kthread, NULL, kicker_main, NULL) != 0) {
    ops->vm_destroy();
    semaphore_destroy(mach_task_self(), g_ksem);
    g_ksem = MACH_PORT_NULL;
    g_vm_ops = NULL;
    rc = VEL1_E_NO_KICKER;
    goto out;
  }
  info->ipa_bits = ipa_bits;
  info->tcr_ips = (uint32_t)ips;
  g_vm_tcr_ips = (uint32_t)ips;
  g_vm_created = true;
out:
  pthread_mutex_unlock(&g_vm_mu);
  return rc;
}

int vel1_vm_destroy(void) {
  pthread_mutex_lock(&g_vm_mu);
  int rc = VEL1_OK;
  if (!g_vm_created || atomic_load(&g_live_vcpus) != 0) {
    rc = VEL1_E_STATE;
    goto out;
  }
  if (g_ksem != MACH_PORT_NULL) {
    atomic_store(&g_kstop, 1);
    semaphore_signal(g_ksem);
    pthread_join(g_kthread, NULL);
    semaphore_destroy(mach_task_self(), g_ksem);
    g_ksem = MACH_PORT_NULL;
  }
  if (g_vm_ops->vm_destroy() != 0) {
    rc = VEL1_E_HV; /* the VM stays "created"; its kicker is already gone */
    goto out;
  }
  g_vm_created = false;
  g_vm_ops = NULL;
out:
  pthread_mutex_unlock(&g_vm_mu);
  return rc;
}

/* ============================================================================================= decode [D6] */
static const char* const k_kind_names[VEL1_EXIT__COUNT] = {
    "NONE", "SYSCALL",  "UNIX_CALL", "HOSTCALL", "FAULT_SYNC",   "ASYNC",   "ILLEGAL", "STAGE2_ABORT",
    "TRAP", "CANCELED", "KICK",      "VTIMER",   "NESTED_FAULT", "UNKNOWN", "ERROR"};
const char* vel1_exit_kind_name(vel1_exit_kind k) { return (unsigned)k < VEL1_EXIT__COUNT ? k_kind_names[k] : "?"; }

static const char* const k_fc_names[VEL1_FC__COUNT] = {
    "NONE",   "UNDEFINED", "WFX",      "FP_ACCESS",  "BTI",        "ILLEGAL_STATE", "SVC",
    "HVC",    "SMC",       "SYSREG",   "INSN_ABORT", "PC_ALIGN",   "DATA_ABORT",    "SP_ALIGN",
    "FP_EXC", "SERROR",    "HW_BREAK", "STEP",       "WATCHPOINT", "BRK",           "OTHER"};
const char* vel1_fault_class_name(vel1_fault_class c) { return (unsigned)c < VEL1_FC__COUNT ? k_fc_names[c] : "?"; }

static const uint8_t k_ec_class[64] = {
    [0x00] = VEL1_FC_UNDEFINED,  [0x01] = VEL1_FC_WFX,        [0x07] = VEL1_FC_FP_ACCESS,
    [0x0D] = VEL1_FC_BTI,        [0x0E] = VEL1_FC_ILLEGAL_STATE, [0x15] = VEL1_FC_SVC,
    [0x16] = VEL1_FC_HVC,        [0x17] = VEL1_FC_SMC,        [0x18] = VEL1_FC_SYSREG,
    [0x19] = VEL1_FC_FP_ACCESS,  [0x1D] = VEL1_FC_FP_ACCESS,  [0x20] = VEL1_FC_INSN_ABORT,
    [0x21] = VEL1_FC_INSN_ABORT, [0x22] = VEL1_FC_PC_ALIGN,   [0x24] = VEL1_FC_DATA_ABORT,
    [0x25] = VEL1_FC_DATA_ABORT, [0x26] = VEL1_FC_SP_ALIGN,   [0x28] = VEL1_FC_FP_EXC,
    [0x2C] = VEL1_FC_FP_EXC,     [0x2F] = VEL1_FC_SERROR,     [0x30] = VEL1_FC_HW_BREAK,
    [0x31] = VEL1_FC_HW_BREAK,   [0x32] = VEL1_FC_STEP,       [0x33] = VEL1_FC_STEP,
    [0x34] = VEL1_FC_WATCHPOINT, [0x35] = VEL1_FC_WATCHPOINT, [0x3C] = VEL1_FC_BRK,
};
vel1_fault_class vel1_fault_class_of_ec(uint32_t ec) {
  if (ec >= 64) return VEL1_FC_OTHER;
  return k_ec_class[ec] ? (vel1_fault_class)k_ec_class[ec] : VEL1_FC_OTHER;
}

vel1_fsc_class vel1_fsc_class_of(uint32_t fsc) {
  fsc &= 0x3f;
  if (fsc <= 0x03) return VEL1_FSC_ADDR_SIZE;
  if (fsc <= 0x07) return VEL1_FSC_TRANSLATION;
  if (fsc <= 0x0B) return VEL1_FSC_ACCESS_FLAG;
  if (fsc <= 0x0F) return VEL1_FSC_PERMISSION;
  if (fsc == 0x10 || (fsc >= 0x14 && fsc <= 0x17)) return VEL1_FSC_EXTERNAL;
  if (fsc == 0x21) return VEL1_FSC_ALIGNMENT;
  if (fsc == 0x30) return VEL1_FSC_TLB_CONFLICT;
  return VEL1_FSC_OTHER;
}

static bool in_range(uint64_t a, uint64_t lo, uint64_t size) { return a >= lo && a - lo < size; }
static bool in_vectors(uint64_t a, const vel1_layout* l) { return in_range(a, l->blob_va, VEL1_VECTORS_SIZE); }
bool vel1_pc_in_blob(uint64_t pc, const vel1_layout* l) { return in_range(pc, l->blob_va, VEL1_BLOB_PAGE); }
static bool is_debug_ec(uint32_t ec) { return ec == 0x3C || (ec >= 0x30 && ec <= 0x35); }
static uint64_t sanitize_cpsr(uint64_t c) { return (c & VEL1_CPSR_NZCV_MASK) | VEL1_CPSR_EL1H_MASKED; } /* [D13] */

static void fill_syndrome(vel1_exit* o, uint64_t esr, uint64_t far) {
  const uint32_t ec = (uint32_t)(esr >> 26) & 0x3f;
  const uint32_t iss = (uint32_t)(esr & 0x1FFFFFF);
  o->esr = esr;
  o->far = far;
  o->ec = ec;
  o->fclass = vel1_fault_class_of_ec(ec);
  switch (o->fclass) {
  case VEL1_FC_SVC:
  case VEL1_FC_HVC:
  case VEL1_FC_SMC:
  case VEL1_FC_BRK: o->iss_imm = (uint16_t)(iss & 0xFFFF); break;
  case VEL1_FC_INSN_ABORT:
  case VEL1_FC_DATA_ABORT:
    o->fsc = (uint8_t)(iss & 0x3f);
    o->fsc_class = vel1_fsc_class_of(o->fsc);
    if (o->fsc_class == VEL1_FSC_TRANSLATION || o->fsc_class == VEL1_FSC_ACCESS_FLAG ||
        o->fsc_class == VEL1_FSC_PERMISSION || o->fsc_class == VEL1_FSC_ADDR_SIZE) {
      o->fsc_level = (uint8_t)(o->fsc & 3);
    }
    o->far_valid = !(iss & (1u << 10)); /* FnV */
    o->s1ptw = (iss >> 7) & 1;
    o->is_write = o->fclass == VEL1_FC_DATA_ABORT && ((iss >> 6) & 1); /* WnR */
    break;
  case VEL1_FC_PC_ALIGN:
  case VEL1_FC_WATCHPOINT: o->far_valid = true; break;
  case VEL1_FC_SYSREG: {
    const uint32_t op0 = (iss >> 20) & 3, op2 = (iss >> 17) & 7, op1 = (iss >> 14) & 7, crn = (iss >> 10) & 15,
                   crm = (iss >> 1) & 15;
    o->sysreg_rt = (uint8_t)((iss >> 5) & 31);
    o->sysreg_is_read = iss & 1;
    o->sysreg_enc = op0 << 14 | op1 << 11 | crn << 7 | crm << 3 | op2;
    break;
  }
  default: break;
  }
}

uint32_t vel1_raw_needs(const vel1_raw_exit* raw, const vel1_layout* lay) {
  (void)lay;
  if (raw->reason != HV_EXIT_REASON_EXCEPTION) return 0;
  const uint32_t ec = (uint32_t)(raw->syndrome >> 26) & 0x3f;
  if (ec == 0x16) {
    const uint32_t imm = (uint32_t)(raw->syndrome & 0xFFFF);
    if (imm >= VEL1_HVC_VEC_BASE && imm < VEL1_HVC_VEC_BASE + 16) return VEL1_HAVE_PC | VEL1_HAVE_EL1SYN;
    return VEL1_HAVE_PC; /* a foreign hvc also needs CPSR: vel1_run fetches it after decoding */
  }
  if (is_debug_ec(ec) || ec == 0x17 || ec == 0x18) return VEL1_HAVE_PC | VEL1_HAVE_CPSR;
  return VEL1_HAVE_PC;
}

static void make_illegal(const vel1_raw_exit* raw, vel1_exit* o, uint64_t insn_pc) {
  o->kind = VEL1_EXIT_ILLEGAL;
  o->elr = insn_pc;
  if (raw->have & VEL1_HAVE_CPSR) {
    o->spsr = raw->cpsr;
    o->nzcv = raw->cpsr & VEL1_CPSR_NZCV_MASK;
  }
}

void vel1_decode(const vel1_raw_exit* raw, const vel1_layout* lay, vel1_exit* o) {
  memset(o, 0, sizeof *o);
  o->hv_reason = raw->reason;
  o->have_pc = (raw->have & VEL1_HAVE_PC) != 0;
  o->pc = o->have_pc ? raw->pc : 0;
  switch (raw->reason) {
  case HV_EXIT_REASON_CANCELED: o->kind = VEL1_EXIT_CANCELED; return;
  case HV_EXIT_REASON_VTIMER_ACTIVATED: o->kind = VEL1_EXIT_VTIMER; return;
  case HV_EXIT_REASON_EXCEPTION: break;
  default: o->kind = VEL1_EXIT_UNKNOWN; return;
  }
  o->exit_syndrome = raw->syndrome;
  o->exit_va = raw->va;
  o->exit_ipa = raw->ipa;
  o->exit_ec = (uint32_t)(raw->syndrome >> 26) & 0x3f;
  const uint64_t b = lay->blob_va;

  if (o->exit_ec == 0x16) {
    const uint32_t imm = (uint32_t)(raw->syndrome & 0xFFFF);
    o->hvc_imm = imm;
    o->iss_imm = (uint16_t)imm;
    o->ec = 0x16;
    o->fclass = VEL1_FC_HVC;
    const uint64_t hvc_va = raw->pc - (VEL1_HVC_PC_IS_NEXT ? 4 : 0); /* [D17] */
    if (imm >= VEL1_HVC_VEC_BASE && imm < VEL1_HVC_VEC_BASE + 16) {
      const uint32_t slot = imm - VEL1_HVC_VEC_BASE;
      const uint64_t slot_va = b + (uint64_t)slot * VEL1_VECTOR_SLOT_SIZE;
      if (o->have_pc && raw->pc != slot_va && raw->pc != slot_va + 4) {
        make_illegal(raw, o, hvc_va); /* a vector immediate executed outside its slot: PE code */
        return;
      }
      o->hvc_pc_is_next = o->have_pc && raw->pc == slot_va + 4;
      if (!(raw->have & VEL1_HAVE_EL1SYN)) {
        o->kind = VEL1_EXIT_UNKNOWN;
        return;
      }
      o->vec_slot = slot;
      o->vec_group = (vel1_vec_group)(slot >> 2);
      o->vec_type = (vel1_vec_type)(slot & 3);
      fill_syndrome(o, raw->esr_el1, raw->far_el1);
      o->elr = raw->elr_el1;
      o->spsr = raw->spsr_el1;
      o->nzcv = raw->spsr_el1 & VEL1_CPSR_NZCV_MASK;
      if (in_vectors(raw->elr_el1, lay)) {
        o->kind = VEL1_EXIT_NESTED_FAULT; /* [D7] the vector itself faulted */
      } else {
        o->kind = o->vec_type == VEL1_VEC_SYNC ? VEL1_EXIT_FAULT_SYNC : VEL1_EXIT_ASYNC;
      }
      return;
    }
    if (imm == VEL1_HVC_SYSCALL || imm == VEL1_HVC_UNIX_CALL) {
      const uint64_t stub = b + (imm == VEL1_HVC_SYSCALL ? VEL1_SYSCALL_STUB_OFF : VEL1_UNIXCALL_STUB_OFF);
      const uint64_t stub_hvc = stub + 4 * VEL1_STUB_HVC_INSN;
      if (o->have_pc && raw->pc != stub_hvc && raw->pc != stub_hvc + 4) {
        make_illegal(raw, o, hvc_va);
        return;
      }
      o->hvc_pc_is_next = o->have_pc && raw->pc == stub_hvc + 4;
      o->kind = imm == VEL1_HVC_SYSCALL ? VEL1_EXIT_SYSCALL : VEL1_EXIT_UNIX_CALL;
      return;
    }
    if (imm >= VEL1_HVC_USER_MIN && o->have_pc && lay->hostcall_hi > lay->hostcall_lo &&
        hvc_va >= lay->hostcall_lo && hvc_va < lay->hostcall_hi) {
      o->hvc_pc_is_next = true; /* by construction of hvc_va; R1 checks the actual address */
      o->kind = VEL1_EXIT_HOSTCALL;
      return;
    }
    make_illegal(raw, o, hvc_va); /* [D17] PE code executed an hvc */
    return;
  }
  if (o->exit_ec == 0x20 || o->exit_ec == 0x24) {
    fill_syndrome(o, raw->syndrome, raw->va);
    o->kind = VEL1_EXIT_STAGE2_ABORT;
    return;
  }
  if (is_debug_ec(o->exit_ec)) { /* [D4] */
    fill_syndrome(o, raw->syndrome, raw->va);
    o->via_exit = true;
    o->elr = raw->pc;
    o->spsr = (raw->have & VEL1_HAVE_CPSR) ? raw->cpsr : 0;
    o->nzcv = o->spsr & VEL1_CPSR_NZCV_MASK;
    o->kind = VEL1_EXIT_FAULT_SYNC;
    return;
  }
  fill_syndrome(o, raw->syndrome, raw->va);
  if (o->exit_ec == 0x17) { /* SMC: ELR = the PC HVF reports (which instruction it names is unproven) */
    make_illegal(raw, o, raw->pc);
    return;
  }
  o->kind = VEL1_EXIT_TRAP;
  o->elr = raw->pc; /* trapped MSR/MRS and WFx: the preferred return is the instruction itself */
  if (raw->have & VEL1_HAVE_CPSR) {
    o->spsr = raw->cpsr;
    o->nzcv = raw->cpsr & VEL1_CPSR_NZCV_MASK;
  }
}

bool vel1_cancel_needs_elr(uint64_t pc, const vel1_layout* lay) {
  return in_vectors(pc, lay) && ((pc - lay->blob_va) & (VEL1_VECTOR_SLOT_SIZE - 1)) == 0;
}

vel1_cancel_action vel1_cancel_decide(bool pending, uint64_t pc, bool have_elr, uint64_t elr,
                                      const vel1_layout* lay) {
  if (!pending) return VEL1_CANCEL_SPURIOUS;
  const uint64_t b = lay->blob_va;
  if (in_vectors(pc, lay)) {
    if (((pc - b) & (VEL1_VECTOR_SLOT_SIZE - 1)) != 0) return VEL1_CANCEL_NESTED_FATAL; /* `b .` or padding */
    if (have_elr && in_vectors(elr, lay)) return VEL1_CANCEL_NESTED_FATAL;            /* recursing fetch fault */
    return VEL1_CANCEL_REENTER_WINDOW; /* vk:1517-1527 */
  }
  if (in_range(pc, b + VEL1_SYSCALL_STUB_OFF, 2 * VEL1_STUB_SIZE)) {
    const uint64_t insn = ((pc - b - VEL1_SYSCALL_STUB_OFF) % VEL1_STUB_SIZE) / 4;
    if ((pc & 3) == 0 && insn <= VEL1_STUB_HVC_INSN) return VEL1_CANCEL_REENTER_WINDOW;
    return VEL1_CANCEL_NESTED_FATAL; /* the ret/udf: no path leaves PC there [D7] */
  }
  if (vel1_pc_in_blob(pc, lay)) return VEL1_CANCEL_NESTED_FATAL;
  return VEL1_CANCEL_REPORT_KICK;
}

/* ================================================================================================= vCPU */
#define HVCHK(v, expr)       \
  do {                       \
    int32_t r_ = (expr);     \
    if (r_) {                \
      (v)->last_hv_err = r_; \
      return VEL1_E_HV;      \
    }                        \
  } while (0)

static bool owner_ok(const vel1_vcpu* v) { return pthread_equal(v->owner, pthread_self()) != 0; }
/* Common guard for every helper that reaches hv_vcpu_* [D12][D16]. */
static int usable(const vel1_vcpu* v) {
  if (!v) return VEL1_E_ARG;
  if (!atomic_load(&v->live)) return VEL1_E_STATE;
  if (!owner_ok(v)) return VEL1_E_WRONG_THREAD;
  if (atomic_load(&v->in_run)) return VEL1_E_STATE; /* from a handler that interrupted vel1_run */
  return VEL1_OK;
}

static int program_vcpu(vel1_vcpu* v, const vel1_vcpu_cfg* c, uint32_t ips) {
  const vel1_hv_ops* o = v->ops;
  const uint64_t id = v->id;
  /* Same order as vk:963-981 (RunDispatcherInVcpu) / vk:1613-1625 (MnVcpuWorkerMain). [D3] */
  HVCHK(v, o->set_sys_reg(id, HV_SYS_REG_MAIR_EL1, VEL1_MAIR_EL1));
  HVCHK(v, o->set_sys_reg(id, HV_SYS_REG_TCR_EL1, VEL1_TCR_EL1(ips)));
  HVCHK(v, o->set_sys_reg(id, HV_SYS_REG_TTBR0_EL1, c->ttbr0));
  HVCHK(v, o->set_sys_reg(id, HV_SYS_REG_VBAR_EL1, c->blob_va + VEL1_VECTORS_OFF));
  HVCHK(v, o->set_sys_reg(id, HV_SYS_REG_CPACR_EL1, VEL1_CPACR_EL1));
  HVCHK(v, o->set_sys_reg(id, HV_SYS_REG_SCTLR_EL1, VEL1_SCTLR_EL1));
  /* [D19] guest CNTVCT_EL0 == mach_absolute_time(): HVF's default first (for the stats), then 0, read back. Here, not
     after the EnTSO block, so the ACTLR read-back stays immediately followed by R4b's debug-trap call [D4]. */
  HVCHK(v, o->get_vtimer_offset(id, &v->vtimer_default));
  if (!(c->flags & VEL1_CFG_KEEP_VTIMER)) {
    HVCHK(v, o->set_vtimer_offset(id, VEL1_VTIMER_OFFSET));
    uint64_t off = ~VEL1_VTIMER_OFFSET;
    HVCHK(v, o->get_vtimer_offset(id, &off));
    if (off != VEL1_VTIMER_OFFSET) return VEL1_E_VTIMER; /* the create's caller destroys the vCPU, as for ENTSO */
  }
  if (!(c->flags & VEL1_CFG_NO_ENTSO)) {
    HVCHK(v, o->set_sys_reg(id, HV_SYS_REG_ACTLR_EL1, VEL1_ACTLR_EL1_ENTSO));
    uint64_t actlr = 0; /* vk:971-975 */
    HVCHK(v, o->get_sys_reg(id, HV_SYS_REG_ACTLR_EL1, &actlr));
    if (((actlr >> 1) & 1u) != 1u) return VEL1_E_ENTSO;
  }
  if (c->flags & VEL1_CFG_CLEAR_DEBUG_TRAP) {
    HVCHK(v, o->set_trap_debug_exceptions(id, false)); /* [D4] R4b only, never run live */
  }
  HVCHK(v, o->set_reg(id, HV_REG_CPSR, sanitize_cpsr(c->cpsr))); /* [D13]: 0x3c5 | NZCV */
  HVCHK(v, o->set_sys_reg(id, HV_SYS_REG_SP_EL1, c->sp_el1));
  HVCHK(v, o->set_reg(id, HV_REG_X0, c->x0));
  HVCHK(v, o->set_reg(id, HV_REG_PC, c->pc));
  return VEL1_OK;
}

int vel1_vcpu_create(vel1_vcpu* v, const vel1_vcpu_cfg* c) {
  if (!v || !c) return VEL1_E_ARG;
  if (c->blob_va & (VEL1_BLOB_PAGE - 1)) return VEL1_E_ARG;
  const vel1_layout lay = {c->blob_va, c->hostcall_lo, c->hostcall_hi};
  if (vel1_pc_in_blob(c->pc, &lay)) return VEL1_E_PC_IN_BLOB;
  if (atomic_load(&v->live)) return VEL1_E_STATE;
  pthread_mutex_lock(&g_vm_mu);
  const bool vm = g_vm_created;
  const vel1_hv_ops* ops = g_vm_ops;
  const uint32_t ips = g_vm_tcr_ips;
  if (vm) atomic_fetch_add(&g_live_vcpus, 1);
  pthread_mutex_unlock(&g_vm_mu);
  if (!vm) return VEL1_E_STATE;

  v->ops = ops;
  v->id = 0;
  v->hv_exit = NULL;
  v->owner = pthread_self();
  v->lay = lay;
  v->flags = c->flags;
  atomic_store(&v->in_run, 0);
  atomic_store(&v->kick_pending, 0);
  atomic_store(&v->kick_req, 0);
  v->destroy_failed = false;
  v->pc_in_blob = false;
  v->logical_valid = 0;
  v->last_hv_err = 0;
  memset(&v->last, 0, sizeof v->last);

  uint64_t id = 0;
  void* hx = NULL;
  int32_t r = ops->vcpu_create(&id, &hx);
  if (r) {
    v->last_hv_err = r;
    atomic_fetch_sub(&g_live_vcpus, 1);
    return VEL1_E_HV;
  }
  v->id = id;
  v->hv_exit = hx;
  int rc = program_vcpu(v, c, ips);
  if (rc == VEL1_OK) { /* register with the kicker [D8] */
    rc = VEL1_E_STATE;
    pthread_mutex_lock(&g_reg_mu);
    for (unsigned i = 0; i < VEL1_MAX_VCPUS; ++i) {
      if (!g_reg[i]) {
        g_reg[i] = v;
        rc = VEL1_OK;
        break;
      }
    }
    pthread_mutex_unlock(&g_reg_mu);
  }
  if (rc != VEL1_OK) {
    if (ops->vcpu_destroy(id) == 0) atomic_fetch_sub(&g_live_vcpus, 1); /* same thread; never published */
    return rc;
  }
  /* G1: publish only once fully created and programmed, under the lifetime lock (vk:1628-1634). */
  os_unfair_lock_lock(&v->life_lock);
  atomic_store(&v->live, 1);
  os_unfair_lock_unlock(&v->life_lock);
  return VEL1_OK;
}

int vel1_vcpu_destroy(vel1_vcpu* v) {
  const int u = usable(v);
  if (u != VEL1_OK) return u;
  pthread_mutex_lock(&g_reg_mu); /* unregister first: lock order g_reg_mu -> life_lock */
  for (unsigned i = 0; i < VEL1_MAX_VCPUS; ++i)
    if (g_reg[i] == v) g_reg[i] = NULL;
  pthread_mutex_unlock(&g_reg_mu);
  /* G1: retire before destroying, under the lock the kicker and a remote kicker hold (vk:1640-1644). */
  os_unfair_lock_lock(&v->life_lock);
  atomic_store(&v->live, 0);
  const int32_t r = v->ops->vcpu_destroy(v->id);
  os_unfair_lock_unlock(&v->life_lock);
  atomic_store(&v->kick_pending, 0);
  atomic_store(&v->kick_req, 0);
  if (r) { /* [D16] the vCPU still exists: keep counting it so vel1_vm_destroy refuses */
    v->last_hv_err = r;
    v->destroy_failed = true;
    return VEL1_E_HV;
  }
  atomic_fetch_sub(&g_live_vcpus, 1);
  return VEL1_OK;
}

/* ============================================================================================ plans [D9] */
void vel1_regs_mask_for(vel1_exit_kind k, uint32_t flags, uint64_t* ci, uint32_t* si, uint64_t* co, uint32_t* so) {
  uint64_t cin = 0, cout = 0;
  uint32_t sin = 0, sout = 0;
  const uint64_t minimal = VEL1_R_X0_X9 | VEL1_R_X(30) | VEL1_R_SP_EL1;
  switch (k) {
  case VEL1_EXIT_SYSCALL:
    if (flags & VEL1_CFG_SYSCALL_MINIMAL_UNSAFE) {
      cin = minimal;
    } else { /* wine signal_arm64.c:1698-1729: x18-x29, sp, x9, x30, NZCV, FPCR, FPSR, q0-q31 (+ x0-x8 args) */
      cin = VEL1_R_X0_X9 | VEL1_R_X18_X29 | VEL1_R_X(30) | VEL1_R_SP_EL1 | VEL1_R_CPSR | VEL1_R_FPCR | VEL1_R_FPSR;
      sin = VEL1_R_ALL_SIMD;
    }
    cout = VEL1_R_X(0) | VEL1_R_X(30) | VEL1_R_PC; /* vel1_syscall_return */
    break;
  case VEL1_EXIT_UNIX_CALL: /* wine signal_arm64.c:1869-1885: x18-x29, q8-q15, x30, sp, NZCV (+ x0-x2 args) */
    cin = VEL1_R_X0_X9 | VEL1_R_X18_X29 | VEL1_R_X(30) | VEL1_R_SP_EL1 | VEL1_R_CPSR;
    sin = VEL1_R_Q8_Q15;
    cout = VEL1_R_X(0) | VEL1_R_PC; /* vel1_call_return */
    break;
  case VEL1_EXIT_HOSTCALL:
    cin = minimal;
    cout = VEL1_R_X(0);
    break;
  case VEL1_EXIT_FAULT_SYNC:
  case VEL1_EXIT_ASYNC:
  case VEL1_EXIT_ILLEGAL:
  case VEL1_EXIT_TRAP:
  case VEL1_EXIT_KICK:
  case VEL1_EXIT_NESTED_FAULT:
    cin = cout = VEL1_R_ALL_CORE & ~VEL1_R_SP_EL0; /* SP_EL0: never touched by any run [D9] */
    sin = sout = VEL1_R_ALL_SIMD;
    break;
  default: break;
  }
  if (ci) *ci = cin;
  if (si) *si = sin;
  if (co) *co = cout;
  if (so) *so = sout;
}

unsigned vel1_regs_accessor_count(uint64_t core, uint32_t simd) {
  return (unsigned)__builtin_popcountll(core & VEL1_R_ALL_CORE) + (unsigned)__builtin_popcount(simd);
}

/* ========================================================================================= registers */
typedef struct {
  uint64_t bit;
  bool sys;
  uint32_t reg;
  size_t off;
} core_reg_desc;
static const core_reg_desc k_core_regs[] = {
    {VEL1_R_PC, false, HV_REG_PC, offsetof(vel1_regs, pc)},
    {VEL1_R_CPSR, false, HV_REG_CPSR, offsetof(vel1_regs, cpsr)},
    {VEL1_R_FPCR, false, HV_REG_FPCR, offsetof(vel1_regs, fpcr)},
    {VEL1_R_FPSR, false, HV_REG_FPSR, offsetof(vel1_regs, fpsr)},
    {VEL1_R_SP_EL0, true, HV_SYS_REG_SP_EL0, offsetof(vel1_regs, sp_el0)},
    {VEL1_R_SP_EL1, true, HV_SYS_REG_SP_EL1, offsetof(vel1_regs, sp_el1)},
    {VEL1_R_TPIDR_EL0, true, HV_SYS_REG_TPIDR_EL0, offsetof(vel1_regs, tpidr_el0)},
    {VEL1_R_TPIDRRO_EL0, true, HV_SYS_REG_TPIDRRO_EL0, offsetof(vel1_regs, tpidrro_el0)},
};

/* The accessor loop without the usable() checks (vel1_run uses it for the call-kind plans). */
static int fetch_regs(vel1_vcpu* v, vel1_regs* r, uint64_t core, uint32_t simd) {
  const vel1_hv_ops* o = v->ops;
  for (unsigned i = 0; i < 31; ++i) {
    if (core & VEL1_R_X(i)) HVCHK(v, o->get_reg(v->id, HV_REG_X0 + i, &r->x[i]));
  }
  for (size_t k = 0; k < sizeof k_core_regs / sizeof k_core_regs[0]; ++k) {
    const core_reg_desc* d = &k_core_regs[k];
    if (!(core & d->bit)) continue;
    uint64_t* dst = (uint64_t*)((uint8_t*)r + d->off);
    if (d->bit == VEL1_R_PC && (v->logical_valid & VEL1_LOGICAL_PC)) { /* [D14] */
      *dst = v->logical_pc;
      continue;
    }
    if (d->bit == VEL1_R_CPSR && (v->logical_valid & VEL1_LOGICAL_CPSR)) {
      *dst = v->logical_cpsr & VEL1_CPSR_NZCV_MASK;
      continue;
    }
    if (d->sys) {
      HVCHK(v, o->get_sys_reg(v->id, (uint16_t)d->reg, dst));
    } else {
      HVCHK(v, o->get_reg(v->id, d->reg, dst));
    }
    if (d->bit == VEL1_R_CPSR) *dst &= VEL1_CPSR_NZCV_MASK; /* [D13] */
  }
  for (unsigned i = 0; i < 32; ++i) {
    if (simd & (1u << i)) HVCHK(v, o->get_simd(v->id, HV_SIMD_FP_REG_Q0 + i, r->v[i]));
  }
  return VEL1_OK;
}

int vel1_regs_get(vel1_vcpu* v, vel1_regs* r, uint64_t core, uint32_t simd) {
  const int u = usable(v);
  if (u != VEL1_OK) return u;
  if (!r) return VEL1_E_ARG;
  return fetch_regs(v, r, core, simd);
}

static void pc_written(vel1_vcpu* v) {
  v->pc_in_blob = false;
  v->logical_valid = 0;
}

int vel1_regs_set(vel1_vcpu* v, const vel1_regs* r, uint64_t core, uint32_t simd) {
  const int u = usable(v);
  if (u != VEL1_OK) return u;
  if (!r) return VEL1_E_ARG;
  if ((core & VEL1_R_PC) && vel1_pc_in_blob(r->pc, &v->lay)) return VEL1_E_PC_IN_BLOB; /* before any write */
  const vel1_hv_ops* o = v->ops;
  for (unsigned i = 0; i < 31; ++i) {
    if (core & VEL1_R_X(i)) HVCHK(v, o->set_reg(v->id, HV_REG_X0 + i, r->x[i]));
  }
  for (size_t k = 0; k < sizeof k_core_regs / sizeof k_core_regs[0]; ++k) {
    const core_reg_desc* d = &k_core_regs[k];
    if (!(core & d->bit)) continue;
    uint64_t val = *(const uint64_t*)((const uint8_t*)r + d->off);
    if (d->bit == VEL1_R_CPSR) val = sanitize_cpsr(val); /* [D13] */
    if (d->sys) {
      HVCHK(v, o->set_sys_reg(v->id, (uint16_t)d->reg, val));
    } else {
      HVCHK(v, o->set_reg(v->id, d->reg, val));
    }
  }
  for (unsigned i = 0; i < 32; ++i) {
    if (simd & (1u << i)) HVCHK(v, o->set_simd(v->id, HV_SIMD_FP_REG_Q0 + i, r->v[i]));
  }
  if (core & VEL1_R_PC) pc_written(v);
  if (core & VEL1_R_CPSR) v->logical_valid &= (uint8_t)~VEL1_LOGICAL_CPSR;
  return VEL1_OK;
}

int vel1_get_cpsr_raw(vel1_vcpu* v, uint64_t* cpsr) {
  const int u = usable(v);
  if (u != VEL1_OK) return u;
  if (!cpsr) return VEL1_E_ARG;
  HVCHK(v, v->ops->get_reg(v->id, HV_REG_CPSR, cpsr));
  return VEL1_OK;
}

/* ================================================================================================= run */
static vel1_exit_kind finish(vel1_vcpu* v, vel1_exit* out, vel1_exit* ex) {
  v->last = *ex;
  *out = *ex;
  return ex->kind;
}
static vel1_exit_kind fail(vel1_vcpu* v, vel1_exit* out, int err, int32_t hv_err) {
  memset(out, 0, sizeof *out);
  out->kind = VEL1_EXIT_ERROR;
  out->err = err;
  out->hv_err = hv_err;
  if (v && hv_err) v->last_hv_err = hv_err;
  return VEL1_EXIT_ERROR; /* v->last is left alone: it still describes the exit the caller must resume from */
}
static vel1_exit_kind report_kick(vel1_vcpu* v, vel1_exit* out, bool have_pc, uint64_t pc) {
  vel1_exit ex;
  memset(&ex, 0, sizeof ex);
  atomic_exchange(&v->kick_pending, 0);
  ex.kind = VEL1_EXIT_KICK;
  ex.have_pc = have_pc;
  ex.pc = pc;
  ++v->kicks_reported;
  return finish(v, out, &ex);
}

vel1_exit_kind vel1_run(vel1_vcpu* v, vel1_exit* out) {
  vel1_exit scratch;
  if (!out) out = &scratch;
  const int u = usable(v);
  if (u != VEL1_OK) return fail(v, out, u, 0);
  if (v->pc_in_blob) return fail(v, out, VEL1_E_NOT_RESUMED, 0); /* [D7] */
  v->logical_valid = 0; /* re-entering with the real PC: any logical view of the last exit is over [D14] */
  const vel1_hv_ops* o = v->ops;
  const uint64_t id = v->id;
  const hv_vcpu_exit_t* hx = (const hv_vcpu_exit_t*)v->hv_exit;
  ++v->runs;
  bool window = false;
  unsigned spurious = 0;
  for (;;) {
    /* G2: in_run first, then the pending check (both seq_cst) [D8]. */
    atomic_store(&v->in_run, 1);
    if (!window && atomic_load(&v->kick_pending)) {
      atomic_store(&v->in_run, 0);
      return report_kick(v, out, false, 0);
    }
    window = false;
    const int32_t rr = o->vcpu_run(id);
    atomic_store(&v->in_run, 0);
    if (rr) return fail(v, out, VEL1_E_HV, rr);
    ++v->exits;

    vel1_raw_exit raw;
    memset(&raw, 0, sizeof raw);
    raw.reason = hx->reason;
    if (raw.reason == HV_EXIT_REASON_EXCEPTION) {
      raw.syndrome = hx->exception.syndrome;
      raw.va = hx->exception.virtual_address;
      raw.ipa = hx->exception.physical_address;
    }
    if (raw.reason == HV_EXIT_REASON_VTIMER_ACTIVATED) { /* vk:1040-1043 */
      ++v->vtimer;
      continue;
    }
    if (raw.reason == HV_EXIT_REASON_CANCELED) {
      if (!atomic_load(&v->kick_pending)) { /* G2: latched leftover */
        ++v->canceled_spurious;
        if (++spurious >= VEL1_MAX_SPURIOUS_CANCELED) {
          vel1_exit ex;
          memset(&ex, 0, sizeof ex);
          ex.kind = VEL1_EXIT_CANCELED;
          ex.hv_reason = raw.reason;
          return finish(v, out, &ex);
        }
        continue;
      }
      uint64_t pc = 0, elr = 0; /* PC read only when a kick is pending (vk:1517-1522) */
      int32_t r = o->get_reg(id, HV_REG_PC, &pc);
      if (r) return fail(v, out, VEL1_E_HV, r);
      const bool need_elr = vel1_cancel_needs_elr(pc, &v->lay);
      if (need_elr) {
        r = o->get_sys_reg(id, HV_SYS_REG_ELR_EL1, &elr);
        if (r) return fail(v, out, VEL1_E_HV, r);
      }
      switch (vel1_cancel_decide(true, pc, need_elr, elr, &v->lay)) {
      case VEL1_CANCEL_REENTER_WINDOW:
        ++v->canceled_window;
        window = true; /* G3 */
        continue;
      case VEL1_CANCEL_NESTED_FATAL: {
        vel1_exit ex;
        memset(&ex, 0, sizeof ex);
        ex.kind = VEL1_EXIT_NESTED_FAULT;
        ex.hv_reason = raw.reason;
        ex.have_pc = true;
        ex.pc = pc;
        ex.elr = elr;
        v->pc_in_blob = true;
        return finish(v, out, &ex);
      }
      case VEL1_CANCEL_REPORT_KICK: return report_kick(v, out, true, pc);
      case VEL1_CANCEL_SPURIOUS: continue; /* unreachable */
      }
    }
    spurious = 0;

    const uint32_t need = vel1_raw_needs(&raw, &v->lay);
    int32_t r = 0;
    if (need & VEL1_HAVE_PC) r = o->get_reg(id, HV_REG_PC, &raw.pc);
    if (!r && (need & VEL1_HAVE_CPSR)) r = o->get_reg(id, HV_REG_CPSR, &raw.cpsr);
    if (!r && (need & VEL1_HAVE_EL1SYN)) { /* vk:1050-1053 */
      r = o->get_sys_reg(id, HV_SYS_REG_ESR_EL1, &raw.esr_el1);
      if (!r) r = o->get_sys_reg(id, HV_SYS_REG_FAR_EL1, &raw.far_el1);
      if (!r) r = o->get_sys_reg(id, HV_SYS_REG_ELR_EL1, &raw.elr_el1);
      if (!r) r = o->get_sys_reg(id, HV_SYS_REG_SPSR_EL1, &raw.spsr_el1);
    }
    if (r) return fail(v, out, VEL1_E_HV, r);
    raw.have = need;

    vel1_exit ex;
    vel1_decode(&raw, &v->lay, &ex);
    switch (ex.kind) {
    case VEL1_EXIT_TRAP:
      if (ex.fclass == VEL1_FC_WFX) { /* [D11] */
        r = o->set_reg(id, HV_REG_PC, raw.pc + 4);
        if (r) return fail(v, out, VEL1_E_HV, r);
        ++v->wfx_stepped;
        continue;
      }
      break;
    case VEL1_EXIT_ILLEGAL:
      if (!(raw.have & VEL1_HAVE_CPSR)) {
        r = o->get_reg(id, HV_REG_CPSR, &ex.spsr);
        if (r) return fail(v, out, VEL1_E_HV, r);
        ex.nzcv = ex.spsr & VEL1_CPSR_NZCV_MASK;
      }
      v->logical_valid = VEL1_LOGICAL_PC; /* PC = the instruction [D14] */
      v->logical_pc = ex.elr;
      break;
    case VEL1_EXIT_SYSCALL:
    case VEL1_EXIT_UNIX_CALL:
    case VEL1_EXIT_HOSTCALL: {
      uint64_t core;
      uint32_t simd;
      vel1_regs_mask_for(ex.kind, v->flags, &core, &simd, NULL, NULL);
      v->logical_valid = 0;
      r = fetch_regs(v, &ex.regs, core, simd);
      if (r) return fail(v, out, r, v->last_hv_err);
      ex.regs_core = core;
      ex.regs_simd = simd;
      if (ex.kind != VEL1_EXIT_HOSTCALL) {
        v->pc_in_blob = true; /* the real PC is the stub's ret until a return helper writes PC [D7] */
        v->logical_valid = VEL1_LOGICAL_PC;
        v->logical_pc = ex.regs.x[30]; /* Wine's frame->pc [D14] */
        ex.regs.pc = ex.regs.x[30];
        ex.regs_core |= VEL1_R_PC;
      }
      break;
    }
    case VEL1_EXIT_FAULT_SYNC:
    case VEL1_EXIT_ASYNC:
    case VEL1_EXIT_NESTED_FAULT:
      if (!ex.via_exit) {
        v->pc_in_blob = true; /* PC sits on the slot's `b .` */
        v->logical_valid = VEL1_LOGICAL_PC | VEL1_LOGICAL_CPSR;
        v->logical_pc = ex.elr;
        v->logical_cpsr = ex.spsr;
      }
      break;
    default: break;
    }
    return finish(v, out, &ex);
  }
}

/* ============================================================================================ resume [D10] */
static int write_pc(vel1_vcpu* v, uint64_t pc) {
  if (vel1_pc_in_blob(pc, &v->lay)) return VEL1_E_PC_IN_BLOB;
  HVCHK(v, v->ops->set_reg(v->id, HV_REG_PC, pc));
  pc_written(v);
  return VEL1_OK;
}

int vel1_resume_at(vel1_vcpu* v, uint64_t pc, uint64_t cpsr) {
  const int u = usable(v);
  if (u != VEL1_OK) return u;
  if (vel1_pc_in_blob(pc, &v->lay)) return VEL1_E_PC_IN_BLOB;
  HVCHK(v, v->ops->set_reg(v->id, HV_REG_PC, pc));                    /* vk:1080 */
  HVCHK(v, v->ops->set_reg(v->id, HV_REG_CPSR, sanitize_cpsr(cpsr))); /* vk:1137, sanitised [D13] */
  pc_written(v);
  return VEL1_OK;
}

int vel1_return_from_vector(vel1_vcpu* v) {
  if (!v) return VEL1_E_ARG;
  const vel1_exit_kind k = v->last.kind;
  if (k != VEL1_EXIT_FAULT_SYNC && k != VEL1_EXIT_ASYNC && k != VEL1_EXIT_ILLEGAL && k != VEL1_EXIT_TRAP) {
    return VEL1_E_STATE;
  }
  return vel1_resume_at(v, v->last.elr, v->last.spsr);
}

int vel1_syscall_return(vel1_vcpu* v, uint64_t x0, uint64_t pc, uint64_t lr) {
  const int u = usable(v);
  if (u != VEL1_OK) return u;
  if (vel1_pc_in_blob(pc, &v->lay)) return VEL1_E_PC_IN_BLOB;
  HVCHK(v, v->ops->set_reg(v->id, HV_REG_X0, x0));
  HVCHK(v, v->ops->set_reg(v->id, HV_REG_X30, lr)); /* frame->lr */
  return write_pc(v, pc);                             /* frame->pc */
}

int vel1_call_return(vel1_vcpu* v, uint64_t x0, uint64_t pc) {
  const int u = usable(v);
  if (u != VEL1_OK) return u;
  if (vel1_pc_in_blob(pc, &v->lay)) return VEL1_E_PC_IN_BLOB;
  HVCHK(v, v->ops->set_reg(v->id, HV_REG_X0, x0));
  return write_pc(v, pc); /* the host plays the stub's ret */
}

int vel1_hostcall_return(vel1_vcpu* v, uint64_t x0) {
  const int u = usable(v);
  if (u != VEL1_OK) return u;
  HVCHK(v, v->ops->set_reg(v->id, HV_REG_X0, x0)); /* PC untouched: resumes after the hvc (hvf_proto smoke) */
  return VEL1_OK;
}

/* ===================================================================================== nested state [D10] */
int vel1_state_save(vel1_vcpu* v, vel1_state* s) {
  const int u = usable(v);
  if (u != VEL1_OK) return u;
  if (!s) return VEL1_E_ARG;
  const vel1_hv_ops* o = v->ops;
  const uint64_t id = v->id;
  s->valid = false;
  /* The MnSaveImage set, in its order (vk:1248-1271). */
  for (unsigned i = 0; i < 31; ++i) HVCHK(v, o->get_reg(id, HV_REG_X0 + i, &s->x[i]));
  HVCHK(v, o->get_reg(id, HV_REG_PC, &s->pc));
  HVCHK(v, o->get_reg(id, HV_REG_CPSR, &s->cpsr_raw));
  HVCHK(v, o->get_reg(id, HV_REG_FPCR, &s->fpcr));
  HVCHK(v, o->get_reg(id, HV_REG_FPSR, &s->fpsr));
  for (unsigned i = 0; i < 32; ++i) HVCHK(v, o->get_simd(id, HV_SIMD_FP_REG_Q0 + i, s->v[i]));
  HVCHK(v, o->get_sys_reg(id, HV_SYS_REG_SP_EL1, &s->sp_el1));
  HVCHK(v, o->get_sys_reg(id, HV_SYS_REG_TPIDR_EL0, &s->tpidr_el0));
  HVCHK(v, o->get_sys_reg(id, HV_SYS_REG_TPIDRRO_EL0, &s->tpidrro_el0));
  HVCHK(v, o->get_sys_reg(id, HV_SYS_REG_TPIDR_EL1, &s->tpidr_el1));
  HVCHK(v, o->get_sys_reg(id, HV_SYS_REG_ELR_EL1, &s->elr_el1));
  HVCHK(v, o->get_sys_reg(id, HV_SYS_REG_SPSR_EL1, &s->spsr_el1));
  HVCHK(v, o->get_sys_reg(id, HV_SYS_REG_ESR_EL1, &s->esr_el1));
  HVCHK(v, o->get_sys_reg(id, HV_SYS_REG_FAR_EL1, &s->far_el1));
  s->pc_in_blob = v->pc_in_blob;
  s->logical_valid = v->logical_valid;
  s->logical_pc = v->logical_pc;
  s->logical_cpsr = v->logical_cpsr;
  s->last = v->last;
  s->valid = true;
  return VEL1_OK;
}

int vel1_state_restore(vel1_vcpu* v, const vel1_state* s) {
  const int u = usable(v);
  if (u != VEL1_OK) return u;
  if (!s || !s->valid) return VEL1_E_ARG;
  const vel1_hv_ops* o = v->ops;
  const uint64_t id = v->id;
  /* The MnLoadImage set, in its order (vk:1277-1300); ESR/FAR are never written. PC and CPSR are values this vCPU
     held when saved, so they are restored raw (the one documented bypass of [D7]/[D13]). */
  for (unsigned i = 0; i < 31; ++i) HVCHK(v, o->set_reg(id, HV_REG_X0 + i, s->x[i]));
  HVCHK(v, o->set_reg(id, HV_REG_PC, s->pc));
  HVCHK(v, o->set_reg(id, HV_REG_CPSR, s->cpsr_raw));
  HVCHK(v, o->set_reg(id, HV_REG_FPCR, s->fpcr));
  HVCHK(v, o->set_reg(id, HV_REG_FPSR, s->fpsr));
  for (unsigned i = 0; i < 32; ++i) HVCHK(v, o->set_simd(id, HV_SIMD_FP_REG_Q0 + i, s->v[i]));
  HVCHK(v, o->set_sys_reg(id, HV_SYS_REG_SP_EL1, s->sp_el1));
  HVCHK(v, o->set_sys_reg(id, HV_SYS_REG_TPIDR_EL0, s->tpidr_el0));
  HVCHK(v, o->set_sys_reg(id, HV_SYS_REG_TPIDRRO_EL0, s->tpidrro_el0));
  HVCHK(v, o->set_sys_reg(id, HV_SYS_REG_TPIDR_EL1, s->tpidr_el1));
  HVCHK(v, o->set_sys_reg(id, HV_SYS_REG_ELR_EL1, s->elr_el1));
  HVCHK(v, o->set_sys_reg(id, HV_SYS_REG_SPSR_EL1, s->spsr_el1));
  v->pc_in_blob = s->pc_in_blob;
  v->logical_valid = s->logical_valid;
  v->logical_pc = s->logical_pc;
  v->logical_cpsr = s->logical_cpsr;
  v->last = s->last;
  return VEL1_OK;
}

int vel1_ctx_save(vel1_vcpu* v, vel1_ctx* c) { /* [D20] */
  const int u = usable(v);
  if (u != VEL1_OK) return u;
  if (!c) return VEL1_E_ARG;
  /* A stub/vector exit (pc_in_blob, the logical PC, last) is saved as is and resumed after the restore exactly as on
     the old vCPU. Only an unresumable state is refused: a NESTED_FAULT last exit (fatal [D7]). */
  if (v->last.kind == VEL1_EXIT_NESTED_FAULT) return VEL1_E_NOT_RESUMED;
  c->version = 0;
  const int r = vel1_state_save(v, &c->st);
  if (r != VEL1_OK) return r;
  HVCHK(v, v->ops->get_sys_reg(v->id, HV_SYS_REG_SP_EL0, &c->sp_el0));
  c->version = VEL1_CTX_VERSION;
  return VEL1_OK;
}

int vel1_ctx_restore(vel1_vcpu* v, const vel1_ctx* c) { /* [D20] */
  const int u = usable(v);
  if (u != VEL1_OK) return u;
  if (!c || c->version != VEL1_CTX_VERSION || !c->st.valid) return VEL1_E_ARG;
  const int r = vel1_state_restore(v, &c->st);
  if (r != VEL1_OK) return r;
  HVCHK(v, v->ops->set_sys_reg(v->id, HV_SYS_REG_SP_EL0, c->sp_el0));
  return VEL1_OK;
}

/* ================================================================================== initiator TLBI [D18] */
/* A fatal stub outcome: the vCPU's PC is somewhere in the blob and its registers are the stub's, so vel1_run must
   refuse to re-enter until the caller writes PC (it never should: the gmm backend aborts on this error). */
static int tlbi_fatal(vel1_vcpu* v, int err, uint32_t reason, uint64_t syndrome, uint64_t pc) {
  v->pc_in_blob = true;
  v->logical_valid = 0;
  v->tlbi_bad_reason = reason;
  v->tlbi_bad_syndrome = syndrome;
  v->tlbi_bad_pc = pc;
  return err;
}
/* Restores x0..x(k-1) (k = 0 for the whole-VMID form: no x register is written), then PC and CPSR, raw. */
static int tlbi_restore(vel1_vcpu* v, const uint64_t* sx, unsigned k, uint64_t pc, uint64_t cpsr) {
  const vel1_hv_ops* o = v->ops;
  for (unsigned i = 0; i < k; ++i) {
    const int32_t r = o->set_reg(v->id, HV_REG_X0 + i, sx[i]);
    if (r) return v->last_hv_err = r, tlbi_fatal(v, VEL1_E_HV, 0, 0, 0);
  }
  int32_t r = o->set_reg(v->id, HV_REG_PC, pc); /* raw: it may be in the blob (a stub or vector exit) [D7] */
  if (!r) r = o->set_reg(v->id, HV_REG_CPSR, cpsr); /* raw: the value this vCPU held [D13] */
  if (r) return v->last_hv_err = r, tlbi_fatal(v, VEL1_E_HV, 0, 0, 0);
  return VEL1_OK;
}

/* One stub run, shared byte-for-byte by both forms [D18]: PC = entry, CPSR = 0x3c5 (EL1h, DAIF masked, whatever PE
   code set), then run until the stub's `hvc #0x102` at `hvc`. VTIMER: re-enter (vk:1040-1043). CANCELED (latched, or
   a kick): PC must lie in [lo, hvc] (else VEL1_E_STUB: e.g. in the vectors, or in the OTHER form's entry); restart at
   `entry` (every TLBI and the final `dsb ish` are re-issued, on whichever PE runs it); more than
   VEL1_MAX_SPURIOUS_CANCELED of them: VEL1_E_BUSY with NOTHING restored (the caller restores, then returns BUSY). Any
   other exit, or the hvc at a PC other than hvc + 4: VEL1_E_STUB via tlbi_fatal. kick_pending is never read or
   taken here. */
static int tlbi_stub_run(vel1_vcpu* v, uint64_t entry, uint64_t lo, uint64_t hvc) {
  const vel1_hv_ops* o = v->ops;
  const uint64_t id = v->id;
  const hv_vcpu_exit_t* hx = (const hv_vcpu_exit_t*)v->hv_exit;
  int32_t r = o->set_reg(id, HV_REG_PC, entry);
  if (!r) r = o->set_reg(id, HV_REG_CPSR, VEL1_CPSR_EL1H_MASKED);
  if (r) return v->last_hv_err = r, tlbi_fatal(v, VEL1_E_HV, 0, 0, 0);
  unsigned canceled = 0;
  for (;;) {
    ++v->tlbi_runs;
    atomic_store(&v->in_run, 1); /* the kicker / kick_remote may exit it; kick_pending is NOT checked or taken */
    const int32_t rr = o->vcpu_run(id);
    atomic_store(&v->in_run, 0);
    if (rr) return v->last_hv_err = rr, tlbi_fatal(v, VEL1_E_HV, 0, 0, 0);
    const uint32_t reason = hx->reason;
    if (reason == HV_EXIT_REASON_VTIMER_ACTIVATED) { /* vk:1040-1043 */
      ++v->tlbi_vtimer;
      continue;
    }
    uint64_t pc = 0;
    if (reason == HV_EXIT_REASON_CANCELED) {
      ++v->tlbi_canceled;
      r = o->get_reg(id, HV_REG_PC, &pc);
      if (r) return v->last_hv_err = r, tlbi_fatal(v, VEL1_E_HV, 0, 0, 0);
      if (pc < lo || pc > hvc) return tlbi_fatal(v, VEL1_E_STUB, reason, 0, pc); /* e.g. in the vectors */
      if (++canceled > VEL1_MAX_SPURIOUS_CANCELED) return VEL1_E_BUSY;
      r = o->set_reg(id, HV_REG_PC, entry); /* restart: every TLBI + the final dsb, on this PE */
      if (r) return v->last_hv_err = r, tlbi_fatal(v, VEL1_E_HV, 0, 0, 0);
      continue;
    }
    const uint64_t syn = reason == HV_EXIT_REASON_EXCEPTION ? hx->exception.syndrome : 0;
    if (reason != HV_EXIT_REASON_EXCEPTION || ((syn >> 26) & 0x3f) != 0x16 || (syn & 0xFFFF) != VEL1_HVC_TLBI_DONE)
      return tlbi_fatal(v, VEL1_E_STUB, reason, syn, 0);
    r = o->get_reg(id, HV_REG_PC, &pc);
    if (r) return v->last_hv_err = r, tlbi_fatal(v, VEL1_E_HV, 0, 0, 0);
    if (pc != hvc + (VEL1_HVC_PC_IS_NEXT ? 4 : 0)) return tlbi_fatal(v, VEL1_E_STUB, reason, syn, pc);
    return VEL1_OK;
  }
}

int vel1_run_tlbi(vel1_vcpu* v, const uint64_t* va, size_t n) {
  const int u = usable(v); /* owner thread, live, and not from a handler inside vel1_run */
  if (u != VEL1_OK) return u;
  if (!va || n == 0 || n > VEL1_TLBI_MAX_VA) return VEL1_E_ARG;
  const vel1_hv_ops* o = v->ops;
  const uint64_t id = v->id;
  const uint64_t stub = v->lay.blob_va + VEL1_TLBI_STUB_OFF, hvc = v->lay.blob_va + VEL1_TLBI_HVC_OFF;
  const unsigned kmax = n < VEL1_TLBI_REGS ? (unsigned)n : VEL1_TLBI_REGS;
  uint64_t save_pc = 0, save_cpsr = 0, sx[VEL1_TLBI_REGS];
  ++v->tlbi_calls;
  /* save exactly what the stub run writes */
  HVCHK(v, o->get_reg(id, HV_REG_PC, &save_pc));
  HVCHK(v, o->get_reg(id, HV_REG_CPSR, &save_cpsr));
  for (unsigned i = 0; i < kmax; ++i) HVCHK(v, o->get_reg(id, HV_REG_X0 + i, &sx[i]));

  for (size_t done = 0; done < n;) {
    const unsigned k = n - done < VEL1_TLBI_REGS ? (unsigned)(n - done) : VEL1_TLBI_REGS;
    const uint64_t entry = v->lay.blob_va + VEL1_TLBI_ENTRY_OFF(k);
    for (unsigned i = 0; i < k; ++i) {
      const int32_t r = o->set_reg(id, HV_REG_X0 + i, (va[done + i] >> 12) & ((1ull << 44) - 1)); /* VA[55:12] */
      if (r) return v->last_hv_err = r, tlbi_fatal(v, VEL1_E_HV, 0, 0, 0);
    }
    const int rc = tlbi_stub_run(v, entry, stub, hvc); /* CANCELED PC bound: the whole VA stub [+0x820, +0x888] */
    if (rc == VEL1_E_BUSY) {
      const int rr = tlbi_restore(v, sx, kmax, save_pc, save_cpsr);
      return rr == VEL1_OK ? VEL1_E_BUSY : rr;
    }
    if (rc != VEL1_OK) return rc;
    done += k;
  }
  return tlbi_restore(v, sx, kmax, save_pc, save_cpsr);
}

int vel1_run_tlbi_all(vel1_vcpu* v) {
  const int u = usable(v); /* owner thread, live, and not from a handler inside vel1_run */
  if (u != VEL1_OK) return u;
  const vel1_hv_ops* o = v->ops;
  const uint64_t id = v->id;
  const uint64_t entry = v->lay.blob_va + VEL1_TLBI_ALL_OFF, hvc = v->lay.blob_va + VEL1_TLBI_ALL_HVC_OFF;
  uint64_t save_pc = 0, save_cpsr = 0;
  ++v->tlbi_calls;
  ++v->tlbi_all_calls;
  /* save exactly what the stub run writes: PC and CPSR (the entry reads no register, so no x register is touched) */
  HVCHK(v, o->get_reg(id, HV_REG_PC, &save_pc));
  HVCHK(v, o->get_reg(id, HV_REG_CPSR, &save_cpsr));
  const int rc = tlbi_stub_run(v, entry, entry, hvc); /* CANCELED PC bound: [+0x890, +0x8A0] */
  if (rc == VEL1_E_BUSY) {
    const int rr = tlbi_restore(v, NULL, 0, save_pc, save_cpsr);
    return rr == VEL1_OK ? VEL1_E_BUSY : rr;
  }
  if (rc != VEL1_OK) return rc;
  return tlbi_restore(v, NULL, 0, save_pc, save_cpsr); /* k = 0: PC and CPSR only, raw */
}

/* ============================================================================================== kicks [D8] */
vel1_kick_result vel1_kick_self(vel1_vcpu* v) {
  /* Async-signal-safe: lock-free atomics, pthread_self (a TSD read), semaphore_signal (a Mach trap). NO hv_* call. */
  if (!v || !atomic_load(&v->live)) {
    if (v) atomic_fetch_add_explicit(&v->kick_not_live, 1, memory_order_relaxed);
    return VEL1_KICK_NOT_LIVE; /* G1 */
  }
  if (!pthread_equal(v->owner, pthread_self())) {
    atomic_fetch_add_explicit(&v->kick_wrong_thread, 1, memory_order_relaxed);
    return VEL1_KICK_WRONG_THREAD;
  }
  atomic_store(&v->kick_pending, 1); /* G2: record first */
  if (!atomic_load(&v->in_run)) {
    atomic_fetch_add_explicit(&v->kick_flag_only, 1, memory_order_relaxed);
    return VEL1_KICK_FLAG_ONLY;
  }
  atomic_store(&v->kick_req, 1);
  if (semaphore_signal(g_ksem) != KERN_SUCCESS) {
    atomic_fetch_add_explicit(&v->kick_signal_failed, 1, memory_order_relaxed);
    return VEL1_KICK_SIGNAL_FAILED;
  }
  atomic_fetch_add_explicit(&v->kick_queued, 1, memory_order_relaxed);
  return VEL1_KICK_QUEUED;
}

vel1_kick_result vel1_kick_remote(vel1_vcpu* v) {
  if (!v) return VEL1_KICK_NOT_LIVE;
  vel1_kick_result res;
  os_unfair_lock_lock(&v->life_lock); /* vk:1366 */
  if (!atomic_load(&v->live)) {
    atomic_fetch_add_explicit(&v->kick_not_live, 1, memory_order_relaxed);
    res = VEL1_KICK_NOT_LIVE;
  } else {
    atomic_store(&v->kick_pending, 1);
    if (!atomic_load(&v->in_run)) {
      atomic_fetch_add_explicit(&v->kick_flag_only, 1, memory_order_relaxed);
      res = VEL1_KICK_FLAG_ONLY;
    } else {
      uint64_t id = v->id;
      if (v->ops->vcpus_exit(&id, 1) != 0) {
        atomic_fetch_add_explicit(&v->kick_signal_failed, 1, memory_order_relaxed);
        res = VEL1_KICK_SIGNAL_FAILED;
      } else {
        atomic_fetch_add_explicit(&v->kick_remote_sent, 1, memory_order_relaxed);
        res = VEL1_KICK_SENT;
      }
    }
  }
  os_unfair_lock_unlock(&v->life_lock);
  return res;
}

bool vel1_kick_pending(vel1_vcpu* v) { return v && atomic_load(&v->kick_pending) != 0; }
bool vel1_kick_take(vel1_vcpu* v) { return v && atomic_exchange(&v->kick_pending, 0) != 0; }
bool vel1_in_guest(vel1_vcpu* v) { return v && atomic_load(&v->in_run) != 0; }

void vel1_get_stats(vel1_vcpu* v, vel1_stats* s) {
  memset(s, 0, sizeof *s);
  if (!v) return;
  s->runs = v->runs;
  s->exits = v->exits;
  s->vtimer = v->vtimer;
  s->canceled_spurious = v->canceled_spurious;
  s->canceled_window = v->canceled_window;
  s->wfx_stepped = v->wfx_stepped;
  s->kicks_reported = v->kicks_reported;
  s->kick_queued = atomic_load(&v->kick_queued);
  s->kick_flag_only = atomic_load(&v->kick_flag_only);
  s->kick_not_live = atomic_load(&v->kick_not_live);
  s->kick_wrong_thread = atomic_load(&v->kick_wrong_thread);
  s->kick_signal_failed = atomic_load(&v->kick_signal_failed);
  s->kick_remote_sent = atomic_load(&v->kick_remote_sent);
  s->kicker_exits = atomic_load(&v->kicker_exits);
  s->tlbi_calls = v->tlbi_calls;
  s->tlbi_runs = v->tlbi_runs;
  s->tlbi_canceled = v->tlbi_canceled;
  s->tlbi_vtimer = v->tlbi_vtimer;
  s->tlbi_all_calls = v->tlbi_all_calls;
  s->vtimer_default = v->vtimer_default;
}
