// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

// Host or guest test of the unwinder's pointer-authentication helpers.
// On arm64 with pointer authentication it signs a code pointer with the IA and
// IB keys and checks that strip and authenticate restore the original; an
// unsigned pointer must come back unchanged from strip. A failed authentication
// (wrong modifier) is run in a child process: without FPAC it returns a
// poisoned, non-canonical pointer; with FPAC it traps and the child is killed
// by a signal. Either way it must never return the original pointer, which is
// what an authenticate replaced by a strip would do. On other targets the
// helpers are the identity and only that is checked.
//
//   cc -march=armv8.3-a -I../src -I../include ptrauth.pass.cpp && ./a.out   (arm64 host)
//   cc -I../src -I../include ptrauth.pass.cpp && ./a.out                    (other hosts)

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

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

// Exit status 0: each failed authentication returned a poisoned pointer.
static int wrongModifierChild(uintptr_t plain) {
  uintptr_t bad[] = {
      __libunwind_auth_ia(sign_ia(plain, 0x1234), 0x1235),
      __libunwind_auth_ib(sign_ib(plain, 0x1234), 0x1235),
  };
  for (uintptr_t b : bad)
    // changed, non-canonical (bits above the address set), and only the
    // signature bits differ from the original
    if (b == plain || (b >> 48) == 0 || __libunwind_strip_code_ptr(b) != plain)
      return 1;
  return 0;
}
static bool wrongModifierIsPoisoned(uintptr_t plain) {
  pid_t pid = fork();
  if (pid == 0)
    _exit(wrongModifierChild(plain));
  int status = 0;
  waitpid(pid, &status, 0);
  return WIFSIGNALED(status) || (WIFEXITED(status) && WEXITSTATUS(status) == 0);
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
    assert(wrongModifierIsPoisoned(plain));
  }
#endif
#if !(defined(__aarch64__) && defined(__LP64__))
  // Not arm64: the helpers are the identity.
  assert(__libunwind_auth_ia(plain, 0) == plain);
  assert(__libunwind_auth_ib(plain, 0) == plain);
#endif
  return 0;
}
