// Package shell provides a reverse shell with automatic reconnection,
// PTY support, and optional Windows evasion integration.
//
// `New(transport, opts) *Shell` wraps any
// [github.com/oioio-space/maldev/c2/transport] implementation in a
// reconnect loop. `Start(ctx)` connects, pipes a local command
// interpreter (cmd.exe direct-I/O on Windows; PTY-allocated /bin/sh
// on Unix via creack/pty) over the transport, and re-establishes the
// connection on disconnect with a configurable retry count and back-off
// delay. `Stop()` and `Wait()` provide deterministic shutdown.
//
// The Windows code path optionally applies AMSI / ETW / CLM / WLDP
// patches and disables PowerShell history before handing the
// transport to the cmd.exe child, satisfying the common red-team
// "land quiet, then live off the land" pattern.
//
// # MITRE ATT&CK
//
//   - T1059 (Command and Scripting Interpreter)
//   - T1059.001 (PowerShell) — when the child is `powershell.exe`
//   - T1059.003 (Windows Command Shell) — when the child is `cmd.exe`
//   - T1059.004 (Unix Shell) — Unix code path
//
// # Detection level
//
// noisy
//
// Reverse-shell traffic patterns are well-known IDS signatures.
// Combine with [github.com/oioio-space/maldev/c2/transport] TLS +
// fingerprint pinning and [github.com/oioio-space/maldev/evasion]
// before connect to dampen host-side telemetry.
//
// # Required privileges
//
// unprivileged for the connect-side implant. Spawning the local
// command interpreter inherits the implant's token, so any
// privilege ceiling required by post-connect activity (file
// access, registry, service control) must already be satisfied
// — `c2/shell` does not elevate. The optional AMSI / ETW / CLM /
// WLDP patches likewise run in-process and need no extra
// privilege beyond the standard own-process write to RX pages.
//
// # Platform
//
// Cross-platform reconnect+pipe loop. cmd.exe direct-I/O is
// Windows-only; Unix builds use a creack/pty PTY around /bin/sh.
// AMSI / ETW / CLM / WLDP patches are Windows-only no-ops on
// other platforms.
//
// # Example
//
// See [ExampleNew] in shell_example_test.go.
//
// # See also
//
//   - docs/techniques/c2/reverse-shell.md
//   - [github.com/oioio-space/maldev/c2/transport] — transport layer
//   - [github.com/oioio-space/maldev/c2/multicat] — operator listener
//   - [github.com/oioio-space/maldev/evasion] — apply AMSI/ETW patches before connect
//
// [github.com/oioio-space/maldev/c2/transport]: https://pkg.go.dev/github.com/oioio-space/maldev/c2/transport
// [github.com/oioio-space/maldev/c2/multicat]: https://pkg.go.dev/github.com/oioio-space/maldev/c2/multicat
// [github.com/oioio-space/maldev/evasion]: https://pkg.go.dev/github.com/oioio-space/maldev/evasion
package shell
