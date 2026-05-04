// Package network provides cross-platform IP address
// retrieval and local-address detection.
//
// Two entry points:
//
//   - [InterfaceIPs] returns every IP on every network
//     interface (loopback, physical, virtual). Used to
//     fingerprint the host for sandbox-detection (looped-back
//     /29 networks are a common sandbox pattern) and for
//     C2 callback-source masking.
//   - [IsLocal] decides whether a given string (IP literal,
//     domain name, or hostname) resolves to one of the host's
//     own interfaces. DNS queries run if the input is a
//     domain name; the result is cached per call.
//
// # MITRE ATT&CK
//
//   - T1016 (System Network Configuration Discovery)
//
// # Detection level
//
// very-quiet
//
// Interface enumeration is universally invisible — every
// network-aware app calls these primitives. DNS lookups
// against unusual domains may surface in DNS telemetry, but
// the package itself only resolves what the caller hands it.
//
// # Required privileges
//
// unprivileged. `net.Interfaces` enumeration uses
// `GetAdaptersAddresses` (Windows) and `getifaddrs(3)`
// (POSIX) — both available to any user. DNS queries
// dispatched by `IsLocal` for non-literal inputs use the
// platform resolver with no privilege requirement.
//
// # Platform
//
// Cross-platform. Pure stdlib `net` package; no build tags.
//
// # Example
//
// See [ExampleInterfaceIPs] in network_example_test.go.
//
// # See also
//
//   - docs/techniques/recon/network.md
//   - [github.com/oioio-space/maldev/c2/transport] — pairs for source-IP awareness
//   - [github.com/oioio-space/maldev/recon/sandbox] — sandbox detection via network
//
// [github.com/oioio-space/maldev/c2/transport]: https://pkg.go.dev/github.com/oioio-space/maldev/c2/transport
// [github.com/oioio-space/maldev/recon/sandbox]: https://pkg.go.dev/github.com/oioio-space/maldev/recon/sandbox
package network
