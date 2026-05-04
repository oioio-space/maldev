// Package imports enumerates a PE's import directory — every DLL
// dependency and every imported function name — without invoking
// any Windows API. The package is pure Go and runs on any host.
//
// Use it to power dynamic API-resolution payloads, build
// per-binary IAT maps for masquerading, or feed downstream
// syscall-discovery tooling. The output is a flat `[]Import`
// slice (DLL, Function, Ordinal) keyed neither by hash nor by
// load order — callers reshape as needed.
//
// # MITRE ATT&CK
//
//   - T1106 (Native API) — discovery of imported APIs to drive runtime resolution
//
// # Detection level
//
// very-quiet
//
// Static analysis only — no syscalls, no file opens beyond the
// caller-supplied path / reader. Runtime invisible.
//
// # Required privileges
//
// unprivileged. Pure-Go offline read of the PE import
// directory; only the read-DACL on the source path applies.
//
// # Platform
//
// Cross-platform. Pure-Go `debug/pe` walker — runs on any
// host the Go toolchain supports.
//
// # Example
//
// See [ExampleList] in imports_example_test.go.
//
// # See also
//
//   - docs/techniques/pe/imports.md
//   - [github.com/oioio-space/maldev/pe/parse] — sibling read-only PE walker
//   - [github.com/oioio-space/maldev/win/syscall] — consumer for SSN extraction
//
// [github.com/oioio-space/maldev/pe/parse]: https://pkg.go.dev/github.com/oioio-space/maldev/pe/parse
// [github.com/oioio-space/maldev/win/syscall]: https://pkg.go.dev/github.com/oioio-space/maldev/win/syscall
package imports
