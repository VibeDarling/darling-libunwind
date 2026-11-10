// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

// Host or guest test of the unwinder's pointer-authentication helpers.
// On arm64 with pointer authentication it signs a code pointer with the IA and
// IB keys and checks that strip and authenticate restore the original; an
// unsigned pointer must come back unchanged from strip. On other targets the
// helpers are the identity and only that is checked. (A wrong-modifier case is
// left to the guest checks: with FPAC it traps instead of returning.)
//
//   cc -march=armv8.3-a -I../src ptrauth.pass.cpp && ./a.out   (arm64 host)
//   cc -I../src ptrauth.pass.cpp && ./a.out                    (other hosts)

#include <assert.h>
#include <stdint.h>

#include "PtrAuth.h"

#if defined(__aarch64__) && defined(__LP64__) && defined(__ARM_FEATURE_PAUTH)
#include <sys/auxv.h>
#ifndef HWCAP_PACA
#define HWCAP_PACA (1 << 30)
#endif
static bool have_pauth() { return getauxval(AT_HWCAP) & HWCAP_PACA; }
static uintptr_t sign_ia(uintptr_t ptr, uintptr_t modifier) {
  __asm__("pacia %0, %1" : "+r"(ptr) : "r"(modifier));
  return ptr;
}
static uintptr_t sign_ib(uintptr_t ptr, uintptr_t modifier) {
  __asm__("pacib %0, %1" : "+r"(ptr) : "r"(modifier));
  return ptr;
}
#endif

static void target() {}

int main() {
  uintptr_t plain = (uintptr_t)&target;
  assert(__libunwind_strip_code_ptr(plain) == plain);
  assert(__libunwind_strip_code_ptr(0) == 0);

#if defined(__aarch64__) && defined(__LP64__) && defined(__ARM_FEATURE_PAUTH)
  if (have_pauth()) {
    uintptr_t modifiers[] = {0, 0x1234, plain};
    for (uintptr_t modifier : modifiers) {
      uintptr_t ia = sign_ia(plain, modifier);
      uintptr_t ib = sign_ib(plain, modifier);
      assert(__libunwind_strip_code_ptr(ia) == plain);
      assert(__libunwind_strip_code_ptr(ib) == plain);
      assert(__libunwind_auth_ia(ia, modifier) == plain);
      assert(__libunwind_auth_ib(ib, modifier) == plain);
    }
  }
#endif
#if !(defined(__aarch64__) && defined(__LP64__))
  // Not arm64: the helpers are the identity.
  assert(__libunwind_auth_ia(plain, 0) == plain);
  assert(__libunwind_auth_ib(plain, 0) == plain);
#endif
  return 0;
}
