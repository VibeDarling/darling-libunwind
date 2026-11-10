//===----------------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Pointer authentication for the unwinder, which is built for plain arm64 and
// runs in processes that mix plain and arm64e images.
//
// A value is authenticated only when the code that produced it is arm64e (a
// frame of an arm64e image, a function pointer into one), because plain code
// never signs. Authentication uses the hint-space forms (autia1716, autib1716,
// with the pointer in x17 and the modifier in x16): they are NOPs on cores
// without pointer authentication, where nothing is signed either. The
// non-hint forms (autia, autiza) are UNDEFINED there. A failed authentication
// leaves a non-canonical pointer that faults when used, or traps at once on
// cores with FPAC; that is the intended result.
//
// Schemes (arm64e Darwin ABI, as emitted by the compiler):
//   return address: IB key, modifier = the SP the function had at entry,
//     which is the CFA of its frame;
//   function pointer (struct field, callback argument): IA key, discriminator 0;
//   GOT slot (personality): IA key, address diversity, discriminator 0, so the
//     modifier is the slot address;
//   landing pad an arm64e personality passes to _Unwind_SetIP: IB key,
//     modifier = the SP of the frame that is resumed.
// __libunwind_strip_code_ptr removes a signature without checking it. It is
// used only to look up which image a pointer belongs to, never for a value
// that is called or installed as a PC.
//
//===----------------------------------------------------------------------===//

#ifndef __PTRAUTH_H__
#define __PTRAUTH_H__

#include <stdint.h>

#include "libunwind_ext.h"

// unw_proc_info_t::flags bits set for a frame whose saved return address is
// signed (the field is otherwise unused for arm64).
#define _LIBUNWIND_RA_SIGNED_IA 0x100u
#define _LIBUNWIND_RA_SIGNED_IB 0x200u
#define _LIBUNWIND_RA_SIGNED_MASK 0x300u

#if defined(__aarch64__) && defined(__LP64__)
// Defined where the helpers below emit hint instructions (LP64 arm64). Everywhere
// else call sites are compiled out so the object code is unchanged.
#define _LIBUNWIND_PTRAUTH_ENABLED 1
#define _LIBUNWIND_PTRAUTH_INLINE static inline __attribute__((always_inline))

// xpaclri is encoded in the hint space (hint #7); it operates on x30.
_LIBUNWIND_PTRAUTH_INLINE uintptr_t __libunwind_strip_code_ptr(uintptr_t ptr) {
  __asm__("mov x30, %0\n\t"
          "hint #7\n\t"
          "mov %0, x30"
          : "+r"(ptr)
          :
          : "x30");
  return ptr;
}

_LIBUNWIND_PTRAUTH_INLINE uintptr_t __libunwind_auth_ia(uintptr_t ptr,
                                                       uintptr_t modifier) {
  register uintptr_t x17 __asm("x17") = ptr;
  register uintptr_t x16 __asm("x16") = modifier;
  __asm__("hint #0xc" : "+r"(x17) : "r"(x16)); // autia1716
  return x17;
}

_LIBUNWIND_PTRAUTH_INLINE uintptr_t __libunwind_auth_ib(uintptr_t ptr,
                                                       uintptr_t modifier) {
  register uintptr_t x17 __asm("x17") = ptr;
  register uintptr_t x16 __asm("x16") = modifier;
  __asm__("hint #0xe" : "+r"(x17) : "r"(x16)); // autib1716
  return x17;
}
#else
#define _LIBUNWIND_PTRAUTH_INLINE static inline __attribute__((always_inline))
_LIBUNWIND_PTRAUTH_INLINE uintptr_t __libunwind_strip_code_ptr(uintptr_t ptr) {
  return ptr;
}
_LIBUNWIND_PTRAUTH_INLINE uintptr_t __libunwind_auth_ia(uintptr_t ptr,
                                                       uintptr_t modifier) {
  (void)modifier;
  return ptr;
}
_LIBUNWIND_PTRAUTH_INLINE uintptr_t __libunwind_auth_ib(uintptr_t ptr,
                                                       uintptr_t modifier) {
  (void)modifier;
  return ptr;
}
#endif

// A code pointer an arm64e caller hands over (a callback, a struct field): IA
// key, discriminator 0. Plain callers hand it over unsigned, so it is
// authenticated only when it points into an arm64e image. The strip is used
// only for that lookup; the pointer that is called is the authenticated one.
#if defined(__aarch64__) && defined(__LP64__)
_LIBUNWIND_PTRAUTH_INLINE uintptr_t __libunwind_auth_function_ptr(uintptr_t ptr) {
  return (ptr && __unw_is_arm64e_code(ptr)) ? __libunwind_auth_ia(ptr, 0) : ptr;
}
#define __libunwind_auth_fn(type, ptr)                                         \
  ((type)__libunwind_auth_function_ptr((uintptr_t)(ptr)))

// The landing pad a personality hands to _Unwind_SetIP. A personality in an
// arm64e image signs it as a return address (IB key, modifier = the SP of the
// frame that is resumed); a plain personality passes a plain address, which must
// not be authenticated. The signer is the personality, so `personality` decides,
// not the frame it unwinds. A pad that fails to authenticate stays poisoned and
// faults when resumed; it is never stripped. Only _Unwind_SetIP authenticates:
// _Unwind_SetGR(UNW_REG_IP, ...) installs the value as given, so a signed pad
// installed that way is never authenticated and fails closed.
//
// Limitation: the personality classified here is the one in the FDE. A
// plain-image wrapper personality that installs a pad signed by an inner arm64e
// personality is classified plain, so the signed pad is installed unchanged and
// the resume faults. That is fail-closed (the pad is never stripped), and it is
// the same approximation used for function pointers; it stays broken for any
// such frame. The mirror case is also fail-closed: an arm64e-image personality
// (or a wrapper in an arm64e image) that installs an unsigned pad has it
// authenticated anyway, so the plain value is installed poisoned and the resume
// faults. Telling the two apart needs scheme detection on the pad itself (try
// IB, then plain), which is not possible without ambiguity today.
_LIBUNWIND_PTRAUTH_INLINE uintptr_t __libunwind_auth_landing_pad(
    uintptr_t pad, uintptr_t sp, uintptr_t personality) {
  return (personality && __unw_is_arm64e_code(personality))
             ? __libunwind_auth_ib(pad, sp)
             : pad;
}
#else
#define __libunwind_auth_fn(type, ptr) (ptr)
#endif

#ifdef __cplusplus
// True when the Mach-O header at `base` is an arm64e image. The low 24 bits of
// cpusubtype are the subtype (2 = arm64e); the top byte carries ABI flags.
template <typename A>
static inline bool __libunwind_image_is_arm64e(A &addressSpace,
                                               uintptr_t base) {
  const uint32_t MH_MAGIC_64 = 0xfeedfacf;
  const uint32_t CPU_TYPE_ARM64 = 0x0100000c;
  return addressSpace.get32(base) == MH_MAGIC_64 &&
         addressSpace.get32(base + 4) == CPU_TYPE_ARM64 &&
         (addressSpace.get32(base + 8) & 0x00ffffff) == 2;
}
#endif

#endif // __PTRAUTH_H__
