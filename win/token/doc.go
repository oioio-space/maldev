//go:build windows

// Package token wraps Windows access-token operations: open/duplicate
// process and thread tokens, steal a token from another PID, enable
// or remove individual privileges, query integrity level, and
// retrieve the active interactive session's primary token.
//
// The [Token] type is a privileged Go-style handle: callers get
// [Token.UserDetails], [Token.Privileges], [Token.IntegrityLevel],
// [Token.LinkedToken] (UAC-paired elevated/non-elevated companion),
// and the privilege-mutation methods (`EnablePrivilege`,
// `DisablePrivilege`, `RemovePrivilege`, plus `*All` and `*Privileges`
// batch variants). Always close with [Token.Close]; [Token.Detach]
// hands ownership to a [windows.Token] caller — useful for
// [windows.CreateProcessAsUser] hand-off.
//
// Steal helpers — [Steal], [StealByName], and [StealViaDuplicateHandle]
// — open the target process with the minimum rights needed
// (`PROCESS_QUERY_LIMITED_INFORMATION`), open its primary token, and
// duplicate it into a `TOKEN_ALL_ACCESS` impersonation handle. From
// there, callers feed the result to
// [github.com/oioio-space/maldev/win/impersonate] or
// [windows.ImpersonateLoggedOnUser] directly.
//
// [Interactive] is the SYSTEM-context shortcut: walk the active WTS
// session, query its user token via `WTSQueryUserToken`, and return
// it as a primary-type [Token] ready for `CreateProcessAsUser`.
//
// Ported from github.com/FourCoreLabs/wintoken with additional
// PID-based steal chain and integrity helpers.
//
// # MITRE ATT&CK
//
//   - T1134 (Access Token Manipulation)
//   - T1134.001 (Token Impersonation/Theft)
//   - T1134.002 (Create Process with Token) — when paired with [windows.CreateProcessAsUser]
//   - T1134.005 (SID-History Injection) — privilege-edit primitives
//
// # Detection level
//
// moderate
//
// `OpenProcess` + `OpenProcessToken` + `DuplicateTokenEx` is a
// classic EDR signal — particularly when targeting `lsass.exe`.
// `SeDebugPrivilege` enablement before the open is itself a
// behavioural marker. Privilege query (`GetTokenInformation`) is
// silent.
//
// # Example
//
// See [ExampleSteal] and [ExampleToken_EnablePrivilege] in token_example_test.go.
//
// # See also
//
//   - docs/techniques/tokens/token-theft.md
//   - [github.com/oioio-space/maldev/win/impersonate] — run callbacks under a stolen token
//   - [github.com/oioio-space/maldev/win/privilege] — companion admin/elevation detection
//
// [github.com/oioio-space/maldev/win/impersonate]: https://pkg.go.dev/github.com/oioio-space/maldev/win/impersonate
// [github.com/oioio-space/maldev/win/privilege]: https://pkg.go.dev/github.com/oioio-space/maldev/win/privilege
package token
