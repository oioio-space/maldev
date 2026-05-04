//go:build windows

// Package cet inspects and relaxes Intel CET (Control-flow Enforcement
// Technology) shadow-stack enforcement for the current process, and
// exposes the ENDBR64 marker required by CET-gated indirect call
// sites.
//
// When a process runs with `ProcessUserShadowStackPolicy` enforced,
// indirect call / return targets must begin with the ENDBR64
// instruction (`F3 0F 1E FA`). Paths that violate this are killed with
// `STATUS_STACK_BUFFER_OVERRUN` (0xC000070A). The most visible impact
// in maldev is APC-dispatched callbacks: `KiUserApcDispatcher` rejects
// shellcode that lacks the marker, breaking
// `inject.CallbackNtNotifyChangeDirectory` and similar APC paths.
//
// Three complementary tools:
//
//   - Enforced — runtime detection. Only call Disable / Wrap when true.
//   - Disable  — best-effort relax of the policy for this process.
//                Fails with `ERROR_NOT_SUPPORTED` if the image was
//                compiled with `/CETCOMPAT`.
//   - Wrap     — prepend Marker (`F3 0F 1E FA`) to a shellcode if not
//                already present. Side-effect-free, idempotent.
//
// Composition pattern (safe order):
//
//	if cet.Enforced() {
//	    if err := cet.Disable(); err != nil {
//	        sc = cet.Wrap(sc)
//	    }
//	}
//
// Disable changes process-global state — call it once at start-up, not
// inside tight loops. Wrap is safe to call unconditionally.
//
// # MITRE ATT&CK
//
//   - T1562.001 (Impair Defenses: Disable or Modify Tools)
//
// # Detection level
//
// noisy
//
// `SetProcessMitigationPolicy` is itself logged by EDR; Defender ASR
// may emit an event when CET is relaxed. Wrap is invisible (it only
// modifies user-supplied shellcode in memory).
//
// # Required privileges
//
// unprivileged. `Enforced` queries the calling process's
// own mitigation-policy state. `Disable` calls
// `SetProcessMitigationPolicy` against the calling
// process — same self-only gate as the other mitigations.
// `Wrap` is pure byte manipulation on a caller-supplied
// shellcode buffer.
//
// # Platform
//
// Windows-only (`//go:build windows`) and amd64-only —
// CET enforcement and the ENDBR64 marker are CPU-feature
// gated. On hosts without CET hardware support `Enforced`
// returns false and `Wrap` is a harmless no-op-prepend.
//
// # Example
//
// See [ExampleEnforced], [ExampleDisable], and [ExampleWrap] in
// cet_example_test.go.
//
// # See also
//
//   - docs/techniques/evasion/cet.md
//   - [github.com/oioio-space/maldev/inject] — ExecuteCallback paths require Marker on Win11+CET hosts
//
// [github.com/oioio-space/maldev/inject]: https://pkg.go.dev/github.com/oioio-space/maldev/inject
package cet
