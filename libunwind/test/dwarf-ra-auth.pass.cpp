// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

// Host test of how the DWARF step treats the return-address rule of a frame in
// an arm64e image. Hand-built CIE and FDE bytes are fed to
// DwarfInstructions::stepWithDwarf with the image flag the cursor would set
// (_LIBUNWIND_RA_SIGNED_IB). Needs pointer authentication; on hosts without it
// the test does nothing. What stays guest-only: the cursor setting the flag from
// the Mach-O header (see the ABI probe, checks 29-32).
//
//   cc -std=c++11 -march=armv8.3-a -D_LIBUNWIND_IS_NATIVE_ONLY -I../src -I../include dwarf-ra-auth.pass.cpp

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "AddressSpace.hpp"
#include "DwarfInstructions.hpp"

#if defined(__aarch64__) && defined(__LP64__) && defined(__ARM_FEATURE_PAUTH)
#include <sys/auxv.h>
using namespace libunwind;

LocalAddressSpace LocalAddressSpace::sThisAddressSpace;
extern "C" bool logDWARF() { return false; }   // normally in libunwind.cpp

typedef DwarfInstructions<LocalAddressSpace, Registers_arm64> Step;

static uintptr_t sign_ia(uintptr_t p, uintptr_t m) { __asm__("pacia %0, %1" : "+r"(p) : "r"(m)); return p; }
static uintptr_t sign_ib(uintptr_t p, uintptr_t m) { __asm__("pacib %0, %1" : "+r"(p) : "r"(m)); return p; }
static uintptr_t strip(uintptr_t p) { __asm__("xpaci %0" : "+r"(p)); return p; }

struct Buf {
  uint8_t b[256] __attribute__((aligned(8)));
  size_t n = 0;
  void u8(uint8_t v) { b[n++] = v; }
  void u32(uint32_t v) { memcpy(b + n, &v, 4); n += 4; }
  void u64(uint64_t v) { memcpy(b + n, &v, 8); n += 8; }
  void str(const char *s) { while (*s) u8((uint8_t)*s++); u8(0); }
  void bytes(const uint8_t *p, size_t len) { memcpy(b + n, p, len); n += len; }
};

// A CIE (augmentation `aug`, return address register `ra`) and an FDE whose
// instructions are def_cfa fp+16 followed by `rule`. Returns the FDE address.
static uintptr_t build(Buf &buf, const char *aug, uint8_t ra, const uint8_t *rule,
                       size_t ruleLen) {
  size_t cie = buf.n;
  buf.u32(0);        // length, patched below
  buf.u32(0);        // CIE id
  buf.u8(1);         // version
  buf.str(aug);
  buf.u8(4);         // code alignment
  buf.u8(0x78);      // data alignment -8
  buf.u8(ra);        // return address register
  buf.u8(1);         // augmentation length
  buf.u8(0);         // 'R': absolute pointers
  const uint8_t init[] = {0x0c, 31, 0};   // def_cfa sp, 0
  buf.bytes(init, sizeof init);
  while ((buf.n - cie) % 8) buf.u8(0);
  uint32_t len = (uint32_t)(buf.n - cie - 4);
  memcpy(buf.b + cie, &len, 4);
  size_t fde = buf.n;
  buf.u32(0);
  buf.u32((uint32_t)(buf.n - cie));       // CIE pointer: back to the CIE start
  buf.u64(0x1000);                        // pc begin
  buf.u64(0x100);                         // pc range
  buf.u8(0);                              // augmentation length
  const uint8_t cfa[] = {0x0c, 29, 16};   // def_cfa fp, 16
  buf.bytes(cfa, sizeof cfa);
  buf.bytes(rule, ruleLen);
  while ((buf.n - fde) % 8) buf.u8(0);
  len = (uint32_t)(buf.n - fde - 4);
  memcpy(buf.b + fde, &len, 4);
  return (uintptr_t)buf.b + fde;
}

static uint64_t g_frame[8] __attribute__((aligned(16)));
static const uintptr_t CFA = (uintptr_t)&g_frame[4];

// Step out of the frame: `slot` is the memory at CFA-8, x17 a register. Returns
// the step result; *ip is the new pc.
static int step(uintptr_t fde, unw_word_t flags, uint64_t slot, uint64_t x17,
                uint64_t *ip) {
  memset(g_frame, 0, sizeof g_frame);
  g_frame[3] = slot;
  Registers_arm64 regs;
  regs.setRegister(UNW_ARM64_FP, CFA - 16);   // the rule says CFA = fp + 16
  regs.setRegister(UNW_ARM64_X17, x17);
  bool signal = false;
  int rc = Step::stepWithDwarf(LocalAddressSpace::sThisAddressSpace, 0x1010, fde,
                               flags, regs, signal);
  *ip = regs.getIP();
  return rc;
}

// Run `f` in a child (a failed authentication may trap with FPAC): true when it
// ends normally with status 0.
template <typename F> static bool childOk(F f) {
  pid_t pid = fork();
  if (pid == 0) _exit(f() ? 0 : 1);
  int st = 0; waitpid(pid, &st, 0);
  return WIFEXITED(st) && WEXITSTATUS(st) == 0;
}
// A step that fails to authenticate leaves a pc that is not `want`, or the child
// is killed by a trap (FPAC).
template <typename F> static bool rejected(F f) {
  pid_t pid = fork();
  if (pid == 0) _exit(f() ? 0 : 1);
  int st = 0; waitpid(pid, &st, 0);
  return WIFSIGNALED(st) || (WIFEXITED(st) && WEXITSTATUS(st) == 0);
}

// A pointer whose IB and IA signatures for CFA and CFA+16 are not all-zero, so
// that "unsigned" and "signed for another frame" really are different values.
static uintptr_t pickPlain() {
  for (uintptr_t p = 0x100003f48;; p += 4)
    if (sign_ib(p, CFA) != p && sign_ib(p, CFA + 16) != p &&
        sign_ia(p, CFA) != p && sign_ib(p, CFA + 16) != sign_ib(p, CFA))
      return p;
}

// A rule that may load the return address from memory: in an arm64e image the
// signed value resumes; a flipped PAC bit, a raw unsigned value and a value
// signed for another frame do not; without the image flag nothing is
// authenticated.
static void memoryRule(const uint8_t *rule, size_t len) {
  Buf buf; uintptr_t fde = build(buf, "zR", 30, rule, len);
  const uintptr_t plain = pickPlain();
  const uint64_t good = sign_ib(plain, CFA);
  uint64_t ip = 0;
  assert(step(fde, _LIBUNWIND_RA_SIGNED_IB, good, 0, &ip) == UNW_STEP_SUCCESS);
  assert(ip == plain);
  const uint64_t slots[] = {good ^ (1ULL << 50), plain, sign_ib(plain, CFA + 16),
                            sign_ia(plain, CFA)};
  for (uint64_t slot : slots)
    assert(rejected([&] {
      uint64_t r = 0;
      step(fde, _LIBUNWIND_RA_SIGNED_IB, slot, 0, &r);
      return r != plain;
    }));
  assert(step(fde, 0, plain, 0, &ip) == UNW_STEP_SUCCESS && ip == plain);
}

int main() {
  if (!(getauxval(AT_HWCAP) & (1 << 30)))
    return 0;
  const uintptr_t plain = pickPlain();
  uint64_t ip;

  // Rules that load from memory.
  const uint8_t inCFA[] = {0x9e, 1};                          // offset r30, -8
  const uint8_t atExpr[] = {0x10, 30, 2, 0x38, 0x1c};         // expression: cfa - 8
  const uint8_t isExpr[] = {0x16, 30, 3, 0x38, 0x1c, 0x06};   // val_expression: *(cfa - 8)
  memoryRule(inCFA, sizeof inCFA);
  memoryRule(atExpr, sizeof atExpr);
  memoryRule(isExpr, sizeof isExpr);

  // Rules that cannot read memory are not authenticated.
  {
    const uint8_t inReg[] = {0x09, 30, 17};                   // register r30, r17
    Buf buf; uintptr_t fde = build(buf, "zR", 30, inReg, sizeof inReg);
    const uint64_t odd = sign_ib(plain, 0x77);   // not a valid pc: must pass through
    assert(step(fde, _LIBUNWIND_RA_SIGNED_IB, 0, odd, &ip) == UNW_STEP_SUCCESS);
    assert(ip == odd);
    Buf buf2; uintptr_t fde2 = build(buf2, "zR", 30, 0, 0);  // r30 not restored
    assert(step(fde2, _LIBUNWIND_RA_SIGNED_IB, plain, 0, &ip) == UNW_STEP_SUCCESS);
    assert(ip == 0);
    // val_offset r30 (CFA plus a constant) is unsupported by the step and aborts,
    // before any authentication question arises.
    const uint8_t offs[] = {0x14, 30, 1};
    Buf buf3; uintptr_t fde3 = build(buf3, "zR", 30, offs, sizeof offs);
    pid_t pid = fork();
    if (pid == 0) { uint64_t r; step(fde3, _LIBUNWIND_RA_SIGNED_IB, 0, 0, &r); _exit(0); }
    int st = 0; waitpid(pid, &st, 0);
    assert(WIFSIGNALED(st) && WTERMSIG(st) == SIGABRT);
  }

  // negate_ra_state: authenticated without the image flag, key from the CIE.
  {
    const uint8_t negate[] = {0x9e, 1, 0x2d};
    Buf a; uintptr_t fa = build(a, "zR", 30, negate, sizeof negate);
    assert(step(fa, 0, sign_ia(plain, CFA), 0, &ip) == UNW_STEP_SUCCESS && ip == plain);
    assert(rejected([&] { uint64_t r; step(fa, 0, sign_ib(plain, CFA), 0, &r); return r != plain; }));
    Buf b; uintptr_t fb = build(b, "zRB", 30, negate, sizeof negate);
    assert(step(fb, 0, sign_ib(plain, CFA), 0, &ip) == UNW_STEP_SUCCESS && ip == plain);
    assert(rejected([&] { uint64_t r; step(fb, 0, sign_ia(plain, CFA), 0, &r); return r != plain; }));
  }

  // Malformed CIE: a return address register beyond the register table is
  // rejected, not used to index it.
  {
    const uint8_t inCFA2[] = {0x9e, 1};
    const uint8_t badRa[] = {96, 200};
    for (uint8_t ra : badRa) {
      Buf buf; uintptr_t fde = build(buf, "zR", ra, inCFA2, sizeof inCFA2);
      assert(childOk([&] {
        uint64_t r;
        return step(fde, _LIBUNWIND_RA_SIGNED_IB, 0, 0, &r) == UNW_EBADFRAME;
      }));
    }
  }
  return 0;
}
#else
int main() { return 0; }
#endif
