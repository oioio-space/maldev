// Package meterpreter implements Metasploit Framework staging — pulls
// a second-stage Meterpreter payload from a `multi/handler` and
// executes it in the current process or a target picked via the
// optional `Config.Injector`.
//
// Three transport flavours are supplied:
//
//   - `TCP` — raw reverse TCP.
//   - `HTTP` — reverse HTTP with the Metasploit URI checksum format.
//   - `HTTPS` — same with TLS, optionally `InsecureSkipVerify` for
//     self-signed handlers.
//
// Stage execution defaults to a minimal self-injection
// (`VirtualAlloc + RtlMoveMemory + VirtualProtect + CreateThread` on
// Windows; `mmap + purego.SyscallN` on Linux). `Config.Injector` overrides
// that path with any [inject.Injector], making the full
// [github.com/oioio-space/maldev/inject] surface (Build, decorators,
// syscall modes, automatic fallback) available for stage delivery.
//
// On Linux `Config.Injector` is unsupported because the Meterpreter
// wrapper protocol requires the live socket fd to receive the ELF
// stage; setting it returns an error.
//
// # MITRE ATT&CK
//
//   - T1059 (Command and Scripting Interpreter)
//   - T1055 (Process Injection) — when `Config.Injector` is set
//   - T1071.001 (Application Layer Protocol: Web Protocols) — HTTP/HTTPS variants
//   - T1095 (Non-Application Layer Protocol) — TCP variant
//
// # Detection level
//
// noisy
//
// Meterpreter staging is a well-known attack pattern. Network
// signatures match all three transport types out of the box on
// Snort/Suricata; AV products fingerprint the Metasploit payload
// stub even encrypted. Pair with `Config.Injector` (preferably
// `MethodEarlyBirdAPC` + indirect syscalls + XOR + CPU delay) to
// blunt the host-side telemetry.
//
// # Required privileges
//
// unprivileged for the default self-injection path (own-process
// VirtualAlloc + CreateThread / mmap). When Config.Injector is
// set, the privilege requirement defers to the chosen
// [inject.Injector] (typically medium-IL same-user / admin to
// cross security boundaries).
//
// # Platform
//
// Cross-platform stager logic. Default self-injection uses
// Windows APIs on Windows and mmap+purego on Linux; both are
// covered. Config.Injector is Windows-only (the Linux wrapper
// protocol needs the live socket fd).
//
// # Example
//
// See [ExampleNewStager] and [ExampleStager_withInjector] in
// meterpreter_example_test.go.
//
// # See also
//
//   - docs/techniques/c2/meterpreter.md
//   - [github.com/oioio-space/maldev/inject] — stage execution surface
//   - [github.com/oioio-space/maldev/c2/transport] — generic transport layer
//
// [github.com/oioio-space/maldev/inject]: https://pkg.go.dev/github.com/oioio-space/maldev/inject
// [github.com/oioio-space/maldev/c2/transport]: https://pkg.go.dev/github.com/oioio-space/maldev/c2/transport
package meterpreter
