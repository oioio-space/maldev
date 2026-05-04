//go:build windows

// Package session enumerates Windows sessions and creates
// processes / impersonates threads inside other users'
// sessions.
//
// Two flavours of cross-session work:
//
//   - [CreateProcessOnActiveSessions] — spawn a process under
//     another user's token with the right environment block,
//     working directory, and station / desktop handles
//     (`winsta0\default` typically). Used to plant per-user
//     persistence on a multi-user host (Citrix, RDS, terminal
//     server) without re-logging-in.
//   - [ImpersonateThreadOnActiveSession] — run a callback on a
//     locked OS thread under alternate credentials, reverting
//     automatically on completion. Useful for filesystem /
//     network operations that need the user's identity but not
//     a full process.
//
// `List` / `Active` enumerate sessions via `WTSEnumerateSessions`
// — `Active` filters to currently-logged-on interactive
// sessions, the targets that matter operationally.
//
// # MITRE ATT&CK
//
//   - T1134.002 (Access Token Manipulation: Create Process with Token)
//   - T1134.001 (Access Token Manipulation: Token Impersonation/Theft)
//
// # Detection level
//
// moderate
//
// Cross-session process creation lights up the Security event
// log when the operator starts spawning under another user's
// token (Event 4624 type 9 — "new credentials"). EDRs that
// correlate process-tree lineage flag svchost-derived
// children launched under a different user as anomalous.
// Plain `WTSEnumerateSessions` is invisible.
//
// # Required privileges
//
// `List` / `Active` are unprivileged
// (`WTSEnumerateSessions` against the local server).
// `CreateProcessOnActiveSessions` and
// `ImpersonateThreadOnActiveSession` require SYSTEM —
// `WTSQueryUserToken` is gated to LocalSystem on a default
// install. Admin alone is insufficient unless paired with
// an explicit SYSTEM hop (`win/impersonate.GetSystem`).
//
// # Platform
//
// Windows-only (`//go:build windows`). The session / WTS /
// window-station model is Windows-only; no POSIX equivalent.
//
// # Example
//
// See [ExampleList] and [ExampleCreateProcessOnActiveSessions]
// in session_example_test.go.
//
// # See also
//
//   - docs/techniques/process/session.md
//   - [github.com/oioio-space/maldev/win/token] — token primitives consumed here
//   - [github.com/oioio-space/maldev/win/impersonate] — sibling impersonation surface
//
// [github.com/oioio-space/maldev/win/token]: https://pkg.go.dev/github.com/oioio-space/maldev/win/token
// [github.com/oioio-space/maldev/win/impersonate]: https://pkg.go.dev/github.com/oioio-space/maldev/win/impersonate
package session
