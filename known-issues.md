## [wrapper-personality-landing-pad] Signed pad gated away when a plain-image personality wraps an arm64e one

**Severity**: medium
**Discovered**: 2026-11-10
**Area**: libunwind (pointer authentication)

`_Unwind_SetIP` authenticates the landing pad only when the FDE's personality is
in an arm64e image (`src/PtrAuth.h`, `__libunwind_auth_landing_pad`). A
plain-image wrapper personality that forwards to an arm64e personality inherits
the inner personality's signing, but the gate keys on the wrapper's image, so
the signed pad is installed unchanged and the resume faults. This is
fail-closed: the pad is never stripped, so no unsigned address is executed.

No current throw path is known to use such a wrapper; if a guest frame does, it
stays broken for that frame. The same image-classification approximation is
already accepted for function pointers.

**Workaround**: none.

**Fix plan**: classify the pad's scheme instead of the personality's image (try
IB first, then plain) if that can be done without ambiguity.
