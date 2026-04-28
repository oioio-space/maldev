//go:build windows

// Package impersonate runs callbacks under an alternate Windows
// security context — by credential, by stolen token, or by piggy-
// backing on a target PID.
//
// Two-step pattern under the hood: obtain a primary or impersonation
// token (`LogonUserW` / `OpenProcessToken` + `DuplicateTokenEx` /
// stolen `Token`), then call `ImpersonateLoggedOnUser` on a
// goroutine that has been pinned to its OS thread via
// [runtime.LockOSThread]. The user-supplied callback runs inside
// that frame; `RevertToSelf` is always issued on a deferred path so
// the thread cannot leak the impersonated context.
//
// High-level entry points:
//
//   - [ImpersonateThread] — credential → impersonation in one call.
//   - [ImpersonateToken] — pre-acquired [token.Token] → impersonation.
//   - [ImpersonateByPID] — duplicate the target PID's token and
//     impersonate.
//   - [GetSystem] — shorthand for impersonating the SYSTEM token of
//     a privileged service (winlogon).
//   - [GetTrustedInstaller] — start the TrustedInstaller service if
//     stopped, then impersonate it.
//   - [RunAsTrustedInstaller] — spawn a process directly under TI
//     without an intermediate impersonation block.
//
// # MITRE ATT&CK
//
//   - T1134.001 (Token Impersonation/Theft)
//   - T1134.002 (Create Process with Token) — RunAsTrustedInstaller path
//   - T1134.004 (Parent PID Spoofing) — when paired with c2/shell PPID-spoof
//
// # Detection level
//
// moderate
//
// `LogonUserW` emits Event ID 4624 (logon) and 4648 (explicit
// credential use) on the target host; impersonation primitives are
// monitored by EDRs through `OpenProcessToken` + `DuplicateTokenEx`
// pairs. `RunAsTrustedInstaller` spawns a child of `services.exe`
// — visible in process-tree telemetry.
//
// # Example
//
// See [ExampleImpersonateThread] and [ExampleGetSystem] in
// impersonate_example_test.go.
//
// # See also
//
//   - docs/techniques/tokens/impersonation.md
//   - [github.com/oioio-space/maldev/win/token] — token enumeration / steal primitives
//   - [github.com/oioio-space/maldev/win/privilege] — companion privilege-detection helpers
//
// [github.com/oioio-space/maldev/win/token]: https://pkg.go.dev/github.com/oioio-space/maldev/win/token
// [github.com/oioio-space/maldev/win/privilege]: https://pkg.go.dev/github.com/oioio-space/maldev/win/privilege
package impersonate
