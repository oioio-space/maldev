// Package cet inspects and relaxes Intel CET (Control-flow Enforcement
// Technology) shadow-stack enforcement for the current process, and
// exposes the ENDBR64 marker required by CET-gated indirect call sites.
//
// Technique: Mitigation manipulation — CET shadow stack opt-out.
// MITRE ATT&CK: T1562.001 (Impair Defenses: Disable or Modify Tools).
// Platform: Windows 11+ on Intel CET-capable CPUs.
// Detection: High — SetProcessMitigationPolicy is itself telemetered by
// EDR; Defender/ASR may log the event.
//
// Why this matters for maldev:
//
// When a process runs with ProcessUserShadowStackPolicy enforced,
// indirect call / return targets must begin with the ENDBR64
// instruction (F3 0F 1E FA). Paths that violate this are killed with
// STATUS_STACK_BUFFER_OVERRUN (0xC000070A). The most visible impact in
// maldev is APC-dispatched callbacks: KiUserApcDispatcher rejects
// shellcode that lacks the marker, breaking inject.CallbackNtNotifyChangeDirectory
// and similar APC paths.
//
// Three complementary tools:
//
//   - Enforced() - runtime detection; only call Disable/Wrap when true.
//   - Disable()  - best-effort relax of the policy for this process.
//                  Fails if the image was compiled with /CETCOMPAT.
//   - Wrap(sc)   - prepend Marker to a shellcode if not already present.
//                  Safe fallback when Disable() is refused.
//
// Composition pattern (safe order):
//
//	if cet.Enforced() {
//	    if err := cet.Disable(); err != nil {
//	        sc = cet.Wrap(sc)
//	    }
//	}
//	inject.ExecuteCallback(sc, inject.CallbackNtNotifyChangeDirectory)
//
// Disable() changes process-global state — call it once at start-up,
// not inside tight loops. Wrap() is side-effect-free and idempotent.
package cet
