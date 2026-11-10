// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

// REQUIRES: linux && aarch64
// ADDITIONAL_COMPILE_FLAGS: -march=armv8.3-a

// Host test of _Unwind_SetIP, the production function from UnwindLevel1.c linked
// against a fake cursor: the personality of an arm64e image hands it a landing
// pad signed with the return-address key (IB) and the SP of the frame that is
// resumed; it must install the plain pad. A pad that does not authenticate is
// installed poisoned (never stripped), and a plain personality's pad is
// installed untouched. The cursor's proc info, registers and the image lookup
// (__unw_is_arm64e_code, true for one function) are fakes. What stays guest-only:
// the cursor holding the authenticated handler and the real image lookup, and
// the whole throw path (ABI probe checks 03-10, 23, 28 on an arm64e libc++abi).
// Needs pointer authentication. Lit selects the test only under "linux &&
// aarch64": both features come from the compiler macros of the configured
// target (a native build leaves config.target_triple empty, so a target= gate
// would silently disable it), and libunwind's test config adds "aarch64" after
// the libcxx parameters are applied, so it follows the flags the suite compiles
// with. The file is empty unless built for Linux arm64: the runtime probe reads
// getauxval(AT_HWCAP) and tests bit 30, HWCAP_PACA, which is Linux's arm64 ABI
// (FreeBSD also has getauxval, with different bits). On arm64/LP64 Linux a
// build without __ARM_FEATURE_PAUTH is rejected at compile time, so a
// misconfigured arm64 job cannot stay green; the HWCAP check then skips
// hardware without pointer authentication. ADDITIONAL_COMPILE_FLAGS passes
// -march=armv8.3-a, which the libcxx test format appends to %{compile_flags};
// the same flag is required for the manual build below.
//
//   cc -march=armv8.3-a -fno-stack-protector -D_LIBUNWIND_IS_NATIVE_ONLY -I../src -I../include -c ../src/UnwindLevel1.c -o setip-auth-l1.o
//   c++ -std=c++11 -march=armv8.3-a -D_LIBUNWIND_IS_NATIVE_ONLY -I../src -I../include setip-auth.pass.cpp setip-auth-l1.o

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "PtrAuth.h"
#include "libunwind.h"
#include "unwind.h"

#if defined(__aarch64__) && defined(__LP64__) && defined(__linux__)
#if !defined(__ARM_FEATURE_PAUTH)
#error "setip-auth.pass.cpp needs pointer authentication: build with -march=armv8.3-a or newer"
#endif
#include <sys/auxv.h>

static void arm64ePersonality() {}
static void plainPersonality() {}
static void landingPad() {}

// What the fake cursor reports. Registers other than SP return a value that no
// test signs with, so reading the wrong register shows.
//
// The cursor is a plain struct, and main reuses one object per personality
// across installs: the fake is stateful. __unw_set_reg records the install but
// deliberately does not adjust `sp` for DW_CFA_GNU_args_size, so this fake
// cannot model that adjustment and cannot show whether authentication uses the
// pre- or post-adjustment SP. That ordering is fixed by reading the signer
// (libc++abi signs the pad with the SP read before the adjustment). Do not
// "improve" the fake by mutating `sp` in __unw_set_reg: later probes reuse the
// same objects and would then read the stale value.
struct FakeCursor {
  bool haveInfo;
  uintptr_t handler;
  uintptr_t sp;
  uintptr_t installed;
  int installs;
};
static const uintptr_t kOtherReg = 0x5555000000;

extern "C" {
int __unw_get_proc_info(unw_cursor_t *c, unw_proc_info_t *info) {
  // Like the real one, fill `info` even when there is no unwind info.
  FakeCursor *f = (FakeCursor *)c;
  memset(info, 0, sizeof(*info));
  info->handler = f->handler;
  info->end_ip = f->haveInfo ? 1 : 0;
  return f->haveInfo ? UNW_ESUCCESS : UNW_ENOINFO;
}
int __unw_get_reg(unw_cursor_t *c, unw_regnum_t reg, unw_word_t *value) {
  *value = reg == UNW_REG_SP ? ((FakeCursor *)c)->sp : kOtherReg + reg;
  return UNW_ESUCCESS;
}
int __unw_set_reg(unw_cursor_t *c, unw_regnum_t reg, unw_word_t value) {
  FakeCursor *f = (FakeCursor *)c;
  if (reg == UNW_REG_IP) {
    f->installed = value;
    ++f->installs;
  }
  return UNW_ESUCCESS;
}
int __unw_is_arm64e_code(uintptr_t addr) {
  return __libunwind_strip_code_ptr(addr) == (uintptr_t)&arm64ePersonality;
}
// The rest of UnwindLevel1.c; none is reached by _Unwind_SetIP.
int __unw_getcontext(unw_context_t *) { return 0; }
int __unw_init_local(unw_cursor_t *, unw_context_t *) { return 0; }
int __unw_step(unw_cursor_t *) { return 0; }
int __unw_resume(unw_cursor_t *) { return 0; }
int __unw_get_proc_name(unw_cursor_t *, char *, size_t, unw_word_t *) {
  return UNW_ENOINFO;
}
bool logAPIs() { return false; }
bool logUnwinding() { return false; }
}

static uintptr_t sign_ia(uintptr_t ptr, uintptr_t modifier) {
  __asm__("pacia %0, %1" : "+r"(ptr) : "r"(modifier));
  return ptr;
}
static uintptr_t sign_ib(uintptr_t ptr, uintptr_t modifier) {
  __asm__("pacib %0, %1" : "+r"(ptr) : "r"(modifier));
  return ptr;
}

static uintptr_t install(FakeCursor &f, uintptr_t value) {
  f.installed = 0;
  f.installs = 0;
  _Unwind_SetIP((struct _Unwind_Context *)&f, value);
  assert(f.installs == 1);
  return f.installed;
}

// A failed authentication returns a poisoned pointer, or traps (FPAC). Run in a
// child: it must never install the plain pad.
static bool poisonedOrTrapped(const FakeCursor &c, uintptr_t value,
                              uintptr_t plain) {
  pid_t pid = fork();
  if (pid == 0) {
    FakeCursor f = c;
    _exit(install(f, value) != plain ? 0 : 1);
  }
  int status = 0;
  waitpid(pid, &status, 0);
  return WIFSIGNALED(status) || (WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int main() {
  if (!(getauxval(AT_HWCAP) & (1 << 30)))
    return 0;

  // Pick an SP for which every wrong signature below differs from the right one
  // (the PAC field is a few bits, so a collision would accept a bad value).
  const uintptr_t pad = (uintptr_t)&landingPad;
  uintptr_t sp = 0x7000001230;
  while (sign_ib(pad, sp) == pad || sign_ib(pad, sp) == sign_ib(pad, 0) ||
         sign_ib(pad, sp) == sign_ib(pad, sp + 16) ||
         sign_ib(pad, sp) == sign_ia(pad, sp) ||
         sign_ib(pad, sp) == sign_ia(pad, 0))
    sp += 16;
  FakeCursor arm64e = {true, (uintptr_t)&arm64ePersonality, sp, 0, 0};
  FakeCursor plain = {true, (uintptr_t)&plainPersonality, sp, 0, 0};

  // The pad signed by an arm64e personality (IB, SP) is installed plain.
  assert(install(arm64e, sign_ib(pad, sp)) == pad);
  // The handler the cursor holds is the authenticated one; a signed copy of the
  // same personality still classifies as arm64e.
  FakeCursor signedHandler = arm64e;
  signedHandler.handler = sign_ib((uintptr_t)&arm64ePersonality, 0);
  assert(install(signedHandler, sign_ib(pad, sp)) == pad);

  // Everything else that does not authenticate is installed poisoned.
  assert(poisonedOrTrapped(arm64e, sign_ib(pad, sp + 16), pad)); // wrong SP
  assert(poisonedOrTrapped(arm64e, sign_ib(pad, 0), pad));       // modifier 0
  assert(poisonedOrTrapped(arm64e, sign_ia(pad, sp), pad));      // wrong key
  assert(poisonedOrTrapped(arm64e, sign_ia(pad, 0), pad));       // key and modifier
  assert(poisonedOrTrapped(arm64e, pad, pad));                   // unsigned
  // Corrupted signature: one bit of the PAC field flipped.
  assert(poisonedOrTrapped(arm64e, sign_ib(pad, sp) ^ (1ull << 52), pad));

  // A plain personality hands over a plain pad: installed as it is, and a value
  // that carries signature bits is not authenticated or stripped either.
  assert(install(plain, pad) == pad);
  const uintptr_t signedPad = sign_ib(pad, sp);
  assert(signedPad != pad && install(plain, signedPad) == signedPad);

  // No personality, no proc info: nothing to classify, value untouched.
  FakeCursor noHandler = {true, 0, sp, 0, 0};
  assert(install(noHandler, pad) == pad);
  assert(install(noHandler, signedPad) == signedPad);
  FakeCursor noInfo = {false, (uintptr_t)&arm64ePersonality, sp, 0, 0};
  assert(install(noInfo, pad) == pad);
  return 0;
}
#else
int main() { return 0; }
#endif
