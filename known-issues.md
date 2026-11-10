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

The mirror case is also fail-closed: an arm64e-image personality (or a wrapper
in an arm64e image) that installs an unsigned pad has it authenticated anyway,
so the plain value is installed poisoned and the resume faults.

**Workaround**: none.

**Fix plan**: classify the pad's scheme instead of the personality's image (try
IB first, then plain) if that can be done without ambiguity.

## [registered-fde-no-arm64e-flags] Registered FDEs get no arm64e personality authentication or RA flag

**Severity**: low
**Discovered**: 2026-11-10
**Area**: libunwind (UnwindCursor, DWARF registered FDEs)

`UnwindCursor::getInfo` finds dynamically registered FDEs through
`getInfoFromFdeCie` with `dso_base = 0`: once via `DwarfFDECache::findFDE`
(`src/UnwindCursor.hpp:2019`) and once via `AddressSpace::findOtherFDE`
(`src/UnwindCursor.hpp:2032`). A zero `dso_base` disables both arm64e steps in
that function: the personality is not authenticated through its GOT slot (IA,
slot modifier) and the frame is not marked `_LIBUNWIND_RA_SIGNED_IB`. A frame
registered that way from an arm64e image is unwound as a plain frame, so a
personality pointer that was signed is called without authentication, and a
signed saved return address is resumed unchanged.

This is pre-existing and fail-closed: nothing is stripped, and the signed value
faults when called or resumed. It affects every FDE reached through these two
paths, including frames registered with `__register_frame`; FDEs found through
their image's unwind sections are unaffected.

**Workaround**: none.

**Fix plan**: recover the image base for a cached FDE (for example from the
address space's section lookup) and pass it as `dso_base`.
