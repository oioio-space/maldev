// Package c2 provides command and control building blocks: reverse
// shells, Meterpreter staging, pluggable transports (TCP / TLS / uTLS /
// named pipe), mTLS certificate helpers, and session multiplexing.
//
// The package itself ships no exported symbols — implants and operator
// tools import the sub-packages they need:
//
//   - c2/transport — pluggable TCP / TLS / uTLS transports + Factory.
//   - c2/transport/namedpipe — Windows named-pipe transport.
//   - c2/cert — operator mTLS certificate generation with pinning.
//   - c2/shell — reverse shell with PTY + automatic reconnect.
//   - c2/meterpreter — Metasploit Meterpreter stager.
//   - c2/multicat — multi-session listener with BANNER wire protocol.
//
// # MITRE ATT&CK
//
//   - T1071 (Application Layer Protocol) — HTTP / TLS transports
//   - T1071.001 (Web Protocols) — HTTP/HTTPS Meterpreter staging
//   - T1573 (Encrypted Channel) — TLS transport with cert pinning
//   - T1573.002 (Asymmetric Cryptography) — mTLS via c2/cert
//   - T1095 (Non-Application Layer Protocol) — raw TCP transport
//   - T1059 (Command and Scripting Interpreter) — c2/shell
//   - T1571 (Non-Standard Port) — c2/multicat operator listener
//
// # Detection level
//
// Varies by sub-package. Plain TCP transport is noisy; TLS with
// fingerprint pinning is moderate; named-pipe local IPC is quiet.
// Each sub-package documents its own detection level.
//
// # Example
//
// See [github.com/oioio-space/maldev/c2/shell] and
// [github.com/oioio-space/maldev/c2/transport] for runnable examples.
//
// # See also
//
//   - docs/techniques/c2/README.md
//   - [github.com/oioio-space/maldev/inject] — pair with c2/meterpreter for stage execution
//   - [github.com/oioio-space/maldev/evasion] — apply before c2/shell handoff
//
// [github.com/oioio-space/maldev/c2/shell]: https://pkg.go.dev/github.com/oioio-space/maldev/c2/shell
// [github.com/oioio-space/maldev/c2/transport]: https://pkg.go.dev/github.com/oioio-space/maldev/c2/transport
// [github.com/oioio-space/maldev/inject]: https://pkg.go.dev/github.com/oioio-space/maldev/inject
// [github.com/oioio-space/maldev/evasion]: https://pkg.go.dev/github.com/oioio-space/maldev/evasion
package c2
