// Package transport provides pluggable network transport
// implementations for C2 communication: plain TCP, TLS with optional
// certificate pinning, and uTLS for JA3/JA4 fingerprint randomisation.
//
// The Transport interface defines `Connect`, `Read`, `Write`, `Close`,
// and `RemoteAddr`. Implementations:
//
//   - TCP — raw socket with configurable dial timeout. Suitable for
//     internal networks or tunnelled traffic.
//   - TLS — encryption layer over TCP. Optional client certs,
//     `InsecureSkipVerify`, and SHA-256 fingerprint pinning that
//     defeats TLS-inspection middleboxes regardless of which trusted
//     CA they hold.
//   - uTLS — TLS handshake with a pinned JA3/JA4 fingerprint
//     (Chrome / Firefox / iOS Safari) so the implant blends with
//     normal browser traffic.
//
// `New(*Config)` is the factory; pick the implementation via
// `Config.UseTLS` / `Config.UseUTLS`.
//
// # MITRE ATT&CK
//
//   - T1071 (Application Layer Protocol) — TLS / uTLS variants
//   - T1573 (Encrypted Channel) — TLS family
//   - T1573.002 (Asymmetric Cryptography) — mTLS via `c2/cert`
//   - T1095 (Non-Application Layer Protocol) — raw TCP variant
//
// # Detection level
//
// moderate
//
// Plain TCP is loud; TLS with self-signed certs is flagged by
// network-monitor heuristics; uTLS with a Chrome fingerprint blends
// with standard browser traffic and degrades to "moderate" detection.
// Pair with `c2/cert` fingerprint pinning to deny TLS-inspection
// proxies.
//
// # Example
//
// See [ExampleNew] in transport_example_test.go.
//
// # See also
//
//   - docs/techniques/c2/transport.md
//   - [github.com/oioio-space/maldev/c2/transport/namedpipe] — Windows pipe transport
//   - [github.com/oioio-space/maldev/c2/cert] — certificate generation + pinning
//   - [github.com/oioio-space/maldev/useragent] — pair with HTTP transports for User-Agent randomisation
//
// [github.com/oioio-space/maldev/c2/transport/namedpipe]: https://pkg.go.dev/github.com/oioio-space/maldev/c2/transport/namedpipe
// [github.com/oioio-space/maldev/c2/cert]: https://pkg.go.dev/github.com/oioio-space/maldev/c2/cert
// [github.com/oioio-space/maldev/useragent]: https://pkg.go.dev/github.com/oioio-space/maldev/useragent
package transport
