//go:build windows

// Package domain queries Windows domain-membership state — whether
// the host is workgroup-only, joined to an Active Directory domain,
// or in an unknown state.
//
// One call: [Name] returns the domain or workgroup name plus a
// [JoinStatus] enum (StatusUnknown / StatusUnjoined / StatusWorkgroup
// / StatusDomain). Implementation is a single
// `NetGetJoinInformation` round-trip on the local netapi32 endpoint —
// no LDAP, no DC contact, no privilege check.
//
// Used by post-exploitation flows to gate behaviour: lateral
// movement and DC-targeted credential harvest only make sense on a
// domain-joined host. Pair with [github.com/oioio-space/maldev/win/version]
// + [github.com/oioio-space/maldev/recon/sandbox] for a full host
// fingerprint before deciding to expand operations.
//
// # MITRE ATT&CK
//
//   - T1082 (System Information Discovery) — host fingerprint
//   - T1016 (System Network Configuration Discovery) — when paired with recon/network
//
// # Detection level
//
// very-quiet
//
// `NetGetJoinInformation` is a benign user-mode RPC call to the local
// LSA — no network traffic, no privilege required, used by built-in
// tools (`whoami /upn`, `dsregcmd /status`).
//
// # Example
//
// See [ExampleName] in domain_example_test.go.
//
// # See also
//
//   - docs/techniques/recon/README.md
//   - [github.com/oioio-space/maldev/win/version] — companion host fingerprint
//   - [github.com/oioio-space/maldev/recon/sandbox] — gate operations on environment shape
//
// [github.com/oioio-space/maldev/win/version]: https://pkg.go.dev/github.com/oioio-space/maldev/win/version
// [github.com/oioio-space/maldev/recon/sandbox]: https://pkg.go.dev/github.com/oioio-space/maldev/recon/sandbox
package domain
