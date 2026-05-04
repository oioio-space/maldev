// Package parse provides PE file parsing and modification utilities.
//
// Wraps the standard library `debug/pe` package with helpers
// tailored to maldev workflows: section enumeration, export
// resolution, header manipulation, and raw byte access for PE
// morphing and sRDI pipelines. The package operates on bytes
// only — every entry point accepts an `io.ReaderAt` or a `[]byte`,
// so analysts can inspect Windows PEs from any host.
//
// # MITRE ATT&CK
//
//   - T1027.002 (Obfuscated Files or Information: Software Packing) — discovery primitive consumed by pe/strip + pe/morph
//
// # Detection level
//
// very-quiet
//
// Offline analysis only — no syscalls, no file opens beyond the
// caller-supplied reader. The package is invisible to runtime
// telemetry.
//
// # Required privileges
//
// unprivileged. Pure-Go `debug/pe` walker over caller-supplied
// bytes; only the read DACL on the source path applies.
//
// # Platform
//
// Cross-platform. Stdlib `debug/pe` runs everywhere — analysts
// can dissect Windows PEs from Linux / macOS / CI without a
// Windows host.
//
// # Example
//
// See [ExampleOpen] in parse_example_test.go.
//
// # See also
//
//   - docs/techniques/pe/README.md
//   - [github.com/oioio-space/maldev/pe/strip] — primary consumer for Go-binary sanitisation
//   - [github.com/oioio-space/maldev/pe/morph] — primary consumer for UPX morphing
//   - [github.com/oioio-space/maldev/pe/imports] — sibling import-table analyser
//
// [github.com/oioio-space/maldev/pe/strip]: https://pkg.go.dev/github.com/oioio-space/maldev/pe/strip
// [github.com/oioio-space/maldev/pe/morph]: https://pkg.go.dev/github.com/oioio-space/maldev/pe/morph
// [github.com/oioio-space/maldev/pe/imports]: https://pkg.go.dev/github.com/oioio-space/maldev/pe/imports
package parse
