// Package namedpipe provides a Windows named-pipe transport
// implementing the [github.com/oioio-space/maldev/c2/transport]
// `Transport` and `Listener` interfaces.
//
// Named pipes are Windows' canonical IPC mechanism, used by SMB, RPC,
// the print spooler, and countless internal services. Pipe-based C2
// traffic blends naturally with normal OS activity on the local host
// or across an SMB peer network — no socket appears in `netstat`,
// no firewall rule is needed, and lateral movement via SMB-routed
// pipes is indistinguishable from legitimate file-share use.
//
// Server side:
//
//	ln, _ := namedpipe.NewListener(`\\.\pipe\myc2`)
//	conn, _ := ln.Accept(ctx)
//
// Client side:
//
//	p := namedpipe.New(`\\.\pipe\myc2`, 5*time.Second)
//	_ = p.Connect(ctx)
//	_, _ = p.Write([]byte("hello"))
//
// # MITRE ATT&CK
//
//   - T1071.001 (Application Layer Protocol: Web Protocols) — pipe
//     traffic over SMB lateral path
//   - T1021.002 (Remote Services: SMB/Windows Admin Shares) — when
//     bound to a remote pipe via the SMB redirector
//
// # Detection level
//
// quiet
//
// Pipe IPC is ubiquitous on Windows. Detection requires per-pipe
// allow-listing or behavioural correlation — far rarer than network
// telemetry. Cross-host pipes raise more signal because SMB session
// auditing catches the share access.
//
// # Required privileges
//
// unprivileged for both client and server when the pipe lives
// under `\\.\pipe\` and the listener sets a permissive DACL
// (the default). Cross-host pipes via SMB (`\\HOST\pipe\name`)
// inherit the SMB session's authentication — typically a domain
// user able to authenticate to the remote IPC$ share. SYSTEM
// listeners may need to widen the pipe DACL explicitly to
// accept low-IL clients (impersonation level is set by the
// client via [SECURITY_QOS]).
//
// # Platform
//
// Windows-only. Build tag `_windows.go` enforces this; importers
// targetting other GOOS values get a build error rather than a
// silent stub.
//
// # Example
//
// See [ExampleNewListener] and [ExampleNew] in namedpipe_example_test.go.
//
// # See also
//
//   - docs/techniques/c2/namedpipe.md
//   - [github.com/oioio-space/maldev/c2/transport] — generic interface
//   - [github.com/oioio-space/maldev/c2/shell] — primary consumer
//
// [github.com/oioio-space/maldev/c2/transport]: https://pkg.go.dev/github.com/oioio-space/maldev/c2/transport
// [github.com/oioio-space/maldev/c2/shell]: https://pkg.go.dev/github.com/oioio-space/maldev/c2/shell
package namedpipe
