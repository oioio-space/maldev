// Package imports enumerates a PE's import surface — both the
// classic IMAGE_IMPORT_DESCRIPTOR table AND the
// IMAGE_DELAY_IMPORT_DESCRIPTOR table — without invoking any
// Windows API. Pure Go via saferwall/pe under the hood; runs on
// any host.
//
// Use it to power dynamic API-resolution payloads, build per-
// binary IAT maps for masquerading, or feed downstream syscall-
// discovery tooling. The output is a flat `[]Import` slice
// (DLL, Function, Ordinal, ByOrdinal, Hint, Delay) keyed neither
// by hash nor by load order — callers reshape as needed.
//
// Modern Windows binaries (Edge: 153 delay imports, Office,
// OneDrive, Teams) route the bulk of their dependencies through
// delay-load. [List] walks both axes; [ListDelay] surfaces only
// the delay-load entries when that's the operator's question.
// The `Import.Delay` flag distinguishes the two flavours per
// entry.
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
// Cross-platform. Pure-Go saferwall walker — runs on any host
// the Go toolchain supports.
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
