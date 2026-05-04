// Package cert provides self-signed X.509 certificate generation and
// fingerprint computation for C2 TLS infrastructure.
//
// `Generate` produces a self-signed certificate + RSA private key in
// PEM format with configurable Organization, CommonName, validity
// window, and key size. The certificate carries both ServerAuth and
// ClientAuth extended-key-usage bits, suitable for mutual TLS between
// implant and operator handler. `Fingerprint` returns the SHA-256 hex
// digest of a PEM certificate; the implant pins this value to defeat
// TLS-inspection middleboxes.
//
// Operations regenerate the certificate at build or deploy time so
// every campaign uses a unique key pair, sidestepping signature-based
// blocklists on certificate hashes.
//
// # MITRE ATT&CK
//
//   - T1573.002 (Encrypted Channel: Asymmetric Cryptography) — mTLS
//     between implant and handler
//   - T1573.001 (Encrypted Channel: Symmetric Cryptography) — TLS
//     session keys derived from the cert pair
//
// # Detection level
//
// quiet
//
// Certificate generation is purely arithmetic. The detectable artefact
// is the resulting TLS handshake on the wire (self-signed by default,
// no chain to a public CA).
//
// # Required privileges
//
// unprivileged. Pure Go crypto/x509 code path, no system calls beyond
// crypto/rand.
//
// # Platform
//
// Cross-platform.
//
// # Example
//
// See [ExampleGenerate] in cert_example_test.go.
//
// # See also
//
//   - docs/techniques/c2/transport.md
//   - [github.com/oioio-space/maldev/c2/transport] — primary consumer
//
// [github.com/oioio-space/maldev/c2/transport]: https://pkg.go.dev/github.com/oioio-space/maldev/c2/transport
package cert
