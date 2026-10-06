// SPDX-License-Identifier: MIT
#include "vel1_acqrel.h"

int vel1_acqrel_crosses16(uint64_t addr, uint32_t size) { return ((addr ^ (addr + size - 1)) >> 4) != 0; }

int vel1_acqrel_decode(uint32_t w, vel1_acqrel* d) {
  uint32_t size_field = w >> 30;
  if (size_field == 0) return 0;  // byte forms never cross a 16-byte boundary
  uint8_t kind;
  int16_t imm = 0;
  if ((w & 0x3FFFFC00u) == 0x08DFFC00u) kind = VEL1_AR_LDAR;
  else if ((w & 0x3FFFFC00u) == 0x38BFC000u) kind = VEL1_AR_LDAPR;
  else if ((w & 0x3FFFFC00u) == 0x089FFC00u) kind = VEL1_AR_STLR;
  else if ((w & 0x3FE00C00u) == 0x19400000u) { kind = VEL1_AR_LDAPR; imm = (int16_t)(((int32_t)(w << 11)) >> 23); }
  else if ((w & 0x3FE00C00u) == 0x19000000u) { kind = VEL1_AR_STLR;  imm = (int16_t)(((int32_t)(w << 11)) >> 23); }
  else return 0;
  d->kind = kind; d->size = (uint8_t)(1u << size_field); d->rt = w & 31; d->rn = (w >> 5) & 31; d->imm = imm;
  return 1;
}

uint64_t vel1_acqrel_perform(const vel1_acqrel* d, void* p, uint64_t value) {
  if (d->kind == VEL1_AR_STLR) {
    __asm__ volatile("dmb ish" ::: "memory");
    switch (d->size) {
    case 2: { uint16_t v = (uint16_t)value; __asm__ volatile("strh %w0, [%1]" :: "r"(v), "r"(p) : "memory"); break; }
    case 4: { uint32_t v = (uint32_t)value; __asm__ volatile("str %w0, [%1]" :: "r"(v), "r"(p) : "memory"); break; }
    default: __asm__ volatile("str %0, [%1]" :: "r"(value), "r"(p) : "memory"); break;
    }
    return 0;
  }
  if (d->kind == VEL1_AR_LDAR) __asm__ volatile("dmb ish" ::: "memory");
  uint64_t r;
  switch (d->size) {
  case 2: { uint32_t v; __asm__ volatile("ldrh %w0, [%1]" : "=r"(v) : "r"(p) : "memory"); r = v; break; }
  case 4: { uint32_t v; __asm__ volatile("ldr %w0, [%1]" : "=r"(v) : "r"(p) : "memory"); r = v; break; }
  default: __asm__ volatile("ldr %0, [%1]" : "=r"(r) : "r"(p) : "memory"); break;
  }
  __asm__ volatile("dmb ishld" ::: "memory");
  return r;
}
