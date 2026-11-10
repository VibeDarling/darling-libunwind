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
//     modifier is the slot address.
// __libunwind_strip_code_ptr removes a signature without checking it. It is
// used only to look up which image a pointer belongs to, never for a value
// that is called or installed as a PC.
//
//===----------------------------------------------------------------------===//

#ifndef __PTRAUTH_H__
#define __PTRAUTH_H__

#include <stdint.h>

// unw_proc_info_t::flags bits set for a frame whose saved return address is
// signed (the field is otherwise unused for arm64).
#define _LIBUNWIND_RA_SIGNED_IA 0x100u
#define _LIBUNWIND_RA_SIGNED_IB 0x200u
#define _LIBUNWIND_RA_SIGNED_MASK 0x300u

#if defined(__aarch64__) && defined(__LP64__)
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

#endif // __PTRAUTH_H__
