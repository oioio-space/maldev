// Package bridge is the bidirectional control channel between a
// hook handler installed inside a target process and the implant
// that placed it. It lets the operator swap hook behaviour at
// runtime without re-injecting the handler shellcode.
//
// Two modes:
//
//   - [Standalone] — autonomous handler with no IPC. Used when the
//     hook decision is hard-coded (e.g., always block + log
//     `MessageBoxW`).
//   - [Connect] — handler attaches to a named pipe / TCP transport
//     and accepts commands (`set-mode`, `mute`, `passthrough`,
//     `uninstall`) from the operator.
//
// Wire format is gob-encoded over the supplied transport, so any
// `io.ReadWriter` works — `c2/transport/namedpipe`,
// `c2/transport.TCP`, or a unit-test `net.Pipe` end. The handler
// side runs the bridge inside its own goroutine; the implant side
// drives commands through the [Controller] returned from `Connect`.
//
// # MITRE ATT&CK
//
//   - T1574.012 (Hijack Execution Flow: Inline Hooking) — IPC
//     control over the hook payload
//   - T1071 (Application Layer Protocol) — when the transport is a
//     network socket
//
// # Detection level
//
// moderate
//
// Named-pipe IPC across PIDs and unexpected outbound TCP from
// hooked processes are common EDR signals. Standalone mode is
// silent (no IPC), but loses runtime configurability.
//
// # Required privileges
//
// unprivileged. The transport (named pipe, TCP socket,
// `net.Pipe`) is operator-supplied — pipe DACL / port
// binding gates apply at transport open time, not inside
// this package. The IPC framing layer is pure-Go gob
// serialisation with no syscall, no token surgery.
//
// # Platform
//
// Cross-platform IPC framing. Pairs naturally with
// `c2/transport/namedpipe` (Windows-only) when the
// hook handler lives inside a Windows process; any
// `io.ReadWriter` works elsewhere.
//
// # Example
//
// See [ExampleStandalone] and [ExampleConnect] in
// bridge_example_test.go.
//
// # See also
//
//   - docs/techniques/evasion/inline-hook.md
//   - [github.com/oioio-space/maldev/evasion/hook] — the inline-hook
//     primitive that consumes this controller
//   - [github.com/oioio-space/maldev/c2/transport/namedpipe] — common transport
//
// [github.com/oioio-space/maldev/evasion/hook]: https://pkg.go.dev/github.com/oioio-space/maldev/evasion/hook
// [github.com/oioio-space/maldev/c2/transport/namedpipe]: https://pkg.go.dev/github.com/oioio-space/maldev/c2/transport/namedpipe
package bridge
