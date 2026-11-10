// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

// Host test of the call-site logic that needs no unwinder: how
// Registers_arm64::normalizeNewLinkRegister uses the step's signing flags and
// the new SP as modifier, and when __libunwind_auth_function_ptr authenticates
// a callback or exception_cleanup pointer. The image lookup the latter makes
// (__unw_is_arm64e_code) is replaced by a fake that says "arm64e" for one
// function. What stays guest-only: the compact-unwind flag, the personality
// slot modifier and the real image lookup (UnwindCursor, libunwind.cpp).
// Needs pointer authentication; on hosts without it the test does nothing.
//
//   cc -march=armv8.3-a -D_LIBUNWIND_IS_NATIVE_ONLY -I../src -I../include ptrauth-callsites.pass.cpp

#include <assert.h>
#include <stdint.h>
#include <sys/wait.h>
#include <unistd.h>

#include "PtrAuth.h"
#include "Registers.hpp"

#if defined(__aarch64__) && defined(__LP64__) && defined(__ARM_FEATURE_PAUTH)
#include <sys/auxv.h>

static void arm64eFn() {}
static void plainFn() {}

extern "C" int __unw_is_arm64e_code(uintptr_t addr) {
  return __libunwind_strip_code_ptr(addr) == (uintptr_t)&arm64eFn;
}

static uintptr_t sign_ia(uintptr_t ptr, uintptr_t modifier) {
  __asm__("pacia %0, %1" : "+r"(ptr) : "r"(modifier));
  return ptr;
}
static uintptr_t sign_ib(uintptr_t ptr, uintptr_t modifier) {
  __asm__("pacib %0, %1" : "+r"(ptr) : "r"(modifier));
  return ptr;
}

// A failed authentication returns a poisoned pointer, or traps (FPAC).
template <typename F> static bool poisonedOrTrapped(F f, uintptr_t plain) {
  pid_t pid = fork();
  if (pid == 0)
    _exit(f() != plain ? 0 : 1);
  int status = 0;
  waitpid(pid, &status, 0);
  return WIFSIGNALED(status) || (WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int main() {
  if (!(getauxval(AT_HWCAP) & (1 << 30)))
    return 0;
  using namespace libunwind;

  // normalizeNewLinkRegister: the modifier is the SP the step just set.
  const uintptr_t sp = 0x7000001230, plain = (uintptr_t)&plainFn;
  Registers_arm64 regs;
  regs.setSP(sp);
  uint64_t lr = sign_ib(plain, sp);
  regs.normalizeNewLinkRegister(lr, _LIBUNWIND_RA_SIGNED_IB);
  assert(lr == plain);
  lr = sign_ia(plain, sp);
  regs.normalizeNewLinkRegister(lr, _LIBUNWIND_RA_SIGNED_IA);
  assert(lr == plain);
  // An unsigned frame (no flag) is left alone, even if the value carries bits.
  lr = sign_ib(plain, sp);
  regs.normalizeNewLinkRegister(lr, 0);
  assert(lr == sign_ib(plain, sp));
  // Wrong SP, wrong key, unsigned value: all fail to authenticate.
  assert(poisonedOrTrapped(
      [&] {
        uint64_t v = sign_ib(plain, sp + 16);
        regs.normalizeNewLinkRegister(v, _LIBUNWIND_RA_SIGNED_IB);
        return v;
      },
      plain));
  assert(poisonedOrTrapped(
      [&] {
        uint64_t v = sign_ia(plain, sp + 16);
        regs.normalizeNewLinkRegister(v, _LIBUNWIND_RA_SIGNED_IA);
        return v;
      },
      plain));
  assert(poisonedOrTrapped(
      [&] {
        uint64_t v = sign_ia(plain, sp);
        regs.normalizeNewLinkRegister(v, _LIBUNWIND_RA_SIGNED_IB);
        return v;
      },
      plain));
  assert(poisonedOrTrapped(
      [&] {
        uint64_t v = plain;
        // PAC field of the correct signature may be zero (1 in 128): pick a
        // modifier for which it is not
        uintptr_t mod = sp;
        while (sign_ib(plain, mod) == plain)
          ++mod;
        regs.setSP(mod);
        regs.normalizeNewLinkRegister(v, _LIBUNWIND_RA_SIGNED_IB);
        return v;
      },
      plain));

  // __libunwind_auth_function_ptr: only a pointer into an arm64e image is
  // authenticated (IA, discriminator 0); a plain pointer is passed through.
  const uintptr_t arm64e = (uintptr_t)&arm64eFn;
  assert(__libunwind_auth_function_ptr(sign_ia(arm64e, 0)) == arm64e);
  assert(__libunwind_auth_function_ptr(plain) == plain);
  assert(__libunwind_auth_function_ptr(0) == 0);
  assert(poisonedOrTrapped([&] { return __libunwind_auth_function_ptr(arm64e); },
                           arm64e));
  assert(poisonedOrTrapped(
      [&] { return __libunwind_auth_function_ptr(sign_ia(arm64e, 8)); }, arm64e));
  return 0;
}
#else
int main() { return 0; }
#endif
