/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 the openrosetta / fex_macos contributors. See vcpu_el1.h for the full MIT text.
 *
 * vvvvvvvvvvvvvvvvvvvvvv  THE ONLY FILE IN vcpu_el1/ THAT CALLS Hypervisor.framework  vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
 *
 * [D1] Thin 1:1 wrappers. Linking this file (and -framework Hypervisor) is what makes a binary able to create a VM.
 * The host-only tests never link it. Anything that calls vel1_vm_create(vel1_hv_live_ops(), ...) CREATES A REAL VM and
 * is user-run only (CLAUDE.md, "Hard safety rules").
 *
 * NEW relative to every earlier run (see README "proven vs not"): hv_vm_config_create / hv_vm_config_set_ipa_size /
 * hv_vm_create(config) (only when ipa_bits != 0), hv_vm_config_get_default_ipa_size, and
 * hv_vcpu_set_trap_debug_exceptions. Everything else is a call hvf_fex_vk.cpp or hvf_sigtest already made live.
 * NEW in vel1-gmm-v4: hv_vcpu_get_vtimer_offset / hv_vcpu_set_vtimer_offset [D19], called by EVERY vCPU create (the
 * first live run is rung RQ).
 */
#include "vcpu_el1.h"

#include <Hypervisor/Hypervisor.h>
#include <os/object.h>
#include <string.h>

static int32_t live_vm_get_max_ipa(uint32_t* bits) { return hv_vm_config_get_max_ipa_size(bits); }
static int32_t live_vm_get_default_ipa(uint32_t* bits) { return hv_vm_config_get_default_ipa_size(bits); }

static int32_t live_vm_create(uint32_t ipa_bits) {
  if (ipa_bits == 0) return hv_vm_create(NULL); /* the proven path */
  hv_vm_config_t cfg = hv_vm_config_create();
  if (!cfg) return HV_NO_RESOURCES;
  hv_return_t r = hv_vm_config_set_ipa_size(cfg, ipa_bits);
  if (r == HV_SUCCESS) r = hv_vm_create(cfg);
  os_release(cfg);
  return r;
}
static int32_t live_vm_destroy(void) { return hv_vm_destroy(); }

static int32_t live_vcpu_create(uint64_t* id, void** hv_exit) {
  hv_vcpu_t v = 0;
  hv_vcpu_exit_t* x = NULL;
  const hv_return_t r = hv_vcpu_create(&v, &x, NULL);
  if (r == HV_SUCCESS) {
    *id = v;
    *hv_exit = x;
  }
  return r;
}
static int32_t live_vcpu_destroy(uint64_t id) { return hv_vcpu_destroy((hv_vcpu_t)id); }
static int32_t live_vcpu_run(uint64_t id) { return hv_vcpu_run((hv_vcpu_t)id); }
static int32_t live_vcpus_exit(uint64_t* ids, uint32_t n) { return hv_vcpus_exit((hv_vcpu_t*)ids, n); }
static int32_t live_get_reg(uint64_t id, uint32_t reg, uint64_t* v) {
  return hv_vcpu_get_reg((hv_vcpu_t)id, (hv_reg_t)reg, v);
}
static int32_t live_set_reg(uint64_t id, uint32_t reg, uint64_t v) {
  return hv_vcpu_set_reg((hv_vcpu_t)id, (hv_reg_t)reg, v);
}
static int32_t live_get_sys_reg(uint64_t id, uint16_t reg, uint64_t* v) {
  return hv_vcpu_get_sys_reg((hv_vcpu_t)id, (hv_sys_reg_t)reg, v);
}
static int32_t live_set_sys_reg(uint64_t id, uint16_t reg, uint64_t v) {
  return hv_vcpu_set_sys_reg((hv_vcpu_t)id, (hv_sys_reg_t)reg, v);
}
static int32_t live_get_simd(uint64_t id, uint32_t reg, uint8_t out[16]) {
  hv_simd_fp_uchar16_t q;
  const hv_return_t r = hv_vcpu_get_simd_fp_reg((hv_vcpu_t)id, (hv_simd_fp_reg_t)reg, &q);
  if (r == HV_SUCCESS) memcpy(out, &q, 16);
  return r;
}
static int32_t live_set_simd(uint64_t id, uint32_t reg, const uint8_t in[16]) {
  hv_simd_fp_uchar16_t q;
  memcpy(&q, in, 16);
  return hv_vcpu_set_simd_fp_reg((hv_vcpu_t)id, (hv_simd_fp_reg_t)reg, q);
}
static int32_t live_set_trap_debug_exceptions(uint64_t id, bool trap) {
  return hv_vcpu_set_trap_debug_exceptions((hv_vcpu_t)id, trap);
}
/* [D19] HVF: CNTVCT_EL0 = mach_absolute_time() - vtimer_offset (hv_vcpu.h). NEW: never called by an earlier run. */
static int32_t live_get_vtimer_offset(uint64_t id, uint64_t* off) {
  return hv_vcpu_get_vtimer_offset((hv_vcpu_t)id, off);
}
static int32_t live_set_vtimer_offset(uint64_t id, uint64_t off) {
  return hv_vcpu_set_vtimer_offset((hv_vcpu_t)id, off);
}

static const vel1_hv_ops k_live_ops = {
    .name = "LIVE",
    .vm_get_max_ipa = live_vm_get_max_ipa,
    .vm_get_default_ipa = live_vm_get_default_ipa,
    .vm_create = live_vm_create,
    .vm_destroy = live_vm_destroy,
    .vcpu_create = live_vcpu_create,
    .vcpu_destroy = live_vcpu_destroy,
    .vcpu_run = live_vcpu_run,
    .vcpus_exit = live_vcpus_exit,
    .get_reg = live_get_reg,
    .set_reg = live_set_reg,
    .get_sys_reg = live_get_sys_reg,
    .set_sys_reg = live_set_sys_reg,
    .get_simd = live_get_simd,
    .set_simd = live_set_simd,
    .set_trap_debug_exceptions = live_set_trap_debug_exceptions,
    .get_vtimer_offset = live_get_vtimer_offset,
    .set_vtimer_offset = live_set_vtimer_offset,
};

const vel1_hv_ops* vel1_hv_live_ops(void) { return &k_live_ops; }
/* ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^  END OF THE Hypervisor.framework FILE  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ */
