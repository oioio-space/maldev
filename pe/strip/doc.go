// Package strip sanitises Go-built PE binaries by removing
// toolchain artefacts that fingerprint the producer:
//
//   - The Go pclntab (Go 1.16+ magic bytes) — wiped, breaking
//     redress, GoReSym, and IDA's `go_parser` plugin.
//   - Go-specific section names (.gopclntab, .gosymtab, etc.)
//     — renamed to neutral aliases.
//   - The PE TimeDateStamp — overwritten with a caller-chosen
//     value (default: project epoch).
//
// [Sanitize] chains the three primitives with sensible defaults;
// individual primitives stay exported so callers can compose
// custom pipelines.
//
// # MITRE ATT&CK
//
//   - T1027.002 (Obfuscated Files or Information: Software Packing) — header + symbol-table scrub
//   - T1027.005 (Indicator Removal from Tools) — pclntab wipe defeats Go-binary signatures
//
// # Detection level
//
// quiet
//
// Modified headers and wiped metadata are unlikely to trigger
// behavioural detections; static scanners lose the Go-specific
// context. Forensic re-analysis on a copy that was hashed
// pre-strip can still surface the modification.
//
// # Required privileges
//
// unprivileged. Pure-byte editor over the PE image; only the
// read+write DACL on the path applies.
//
// # Platform
//
// Cross-platform. Pure-Go offline editor — wipe pclntab,
// rename Go sections, scrub TimeDateStamp from any host.
//
// # Example
//
// See [ExampleSanitize] in strip_example_test.go.
//
// # See also
//
//   - docs/techniques/pe/strip-sanitize.md
//   - [github.com/oioio-space/maldev/pe/morph] — UPX header morph; pair with strip for full scrub
//   - [github.com/oioio-space/maldev/pe/cert] — strip/replace Authenticode after sanitisation
//
// [github.com/oioio-space/maldev/pe/morph]: https://pkg.go.dev/github.com/oioio-space/maldev/pe/morph
// [github.com/oioio-space/maldev/pe/cert]: https://pkg.go.dev/github.com/oioio-space/maldev/pe/cert
package strip
