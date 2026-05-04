//go:build windows

// Package privilege answers two operational questions: am I admin
// right now, and how do I run something else as a different
// principal? It wraps `IsAdmin` / `IsAdminGroupMember` for
// privilege detection and three execution primitives — `ExecAs`,
// `CreateProcessWithLogon`, `ShellExecuteRunAs` — for spawning
// processes under alternate credentials.
//
// [IsAdmin] returns both the "am I in the Administrators group" and
// "is my token actually elevated" answers — the second matters on UAC
// hosts where membership alone isn't enough. [ExecAs] is the
// general-purpose path: `LogonUserW` + token-based [exec.Cmd], so
// callers get standard `*exec.Cmd` ergonomics (Stdout pipe, Wait,
// context cancellation). [CreateProcessWithLogon] calls the Win32
// API directly through the Secondary Logon service — useful when an
// `*exec.Cmd` envelope is undesired. [ShellExecuteRunAs] triggers a
// visible UAC consent prompt — operationally noisy, but the only
// option when you have no credentials and need elevation from the
// current interactive session.
//
// Pair with [github.com/oioio-space/maldev/win/token] when you need
// fine-grained token edits (privilege enable/disable) and with
// [github.com/oioio-space/maldev/privesc/uac] when you want to skip
// the consent prompt entirely.
//
// # MITRE ATT&CK
//
//   - T1134 (Access Token Manipulation)
//   - T1548.002 (Bypass User Account Control) — when paired with privesc/uac
//   - T1078 (Valid Accounts) — alternate-credential execution
//
// # Detection level
//
// moderate
//
// `IsAdmin` is silent (token query). `ExecAs` /
// `CreateProcessWithLogon` create Logon events 4624/4648; the spawned
// child appears under `seclogon` lineage in process-tree telemetry.
// `ShellExecuteRunAs` triggers a user-visible UAC dialog and an
// elevated-launch event — high-noise.
//
// # Required privileges
//
// `IsAdmin` / `IsAdminGroupMember` are unprivileged token
// queries. `ExecAs` / `CreateProcessWithLogon` need valid
// credentials for the target principal but no extra privilege
// beyond that — Secondary Logon performs the actual elevation.
// `ShellExecuteRunAs` requires an interactive session (UAC
// prompt cannot render in session 0); the spawned child runs
// elevated only after user consent.
//
// # Platform
//
// Windows-only (`//go:build windows`). Token model + Secondary
// Logon + UAC are Windows constructs.
//
// # Example
//
// See [ExampleIsAdmin] and [ExampleExecAs] in privilege_example_test.go.
//
// # See also
//
//   - docs/techniques/tokens/privilege-escalation.md
//   - [github.com/oioio-space/maldev/win/token] — fine-grained token-privilege edits
//   - [github.com/oioio-space/maldev/privesc/uac] — UAC bypasses (no consent prompt)
//
// [github.com/oioio-space/maldev/win/token]: https://pkg.go.dev/github.com/oioio-space/maldev/win/token
// [github.com/oioio-space/maldev/privesc/uac]: https://pkg.go.dev/github.com/oioio-space/maldev/privesc/uac
package privilege
