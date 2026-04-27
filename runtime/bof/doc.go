// Package bof loads and executes Beacon Object Files (BOFs) —
// compiled COFF object files (`.o`) — entirely in process memory.
//
// A BOF is a relocatable COFF object that runs in the calling
// process's address space. The loader parses the COFF header,
// locates the `.text` section, applies relocations
// (`IMAGE_REL_AMD64_ADDR64`, `IMAGE_REL_AMD64_ADDR32NB`,
// `IMAGE_REL_AMD64_REL32`), resolves the entry-point symbol from
// the symbol table, and jumps into RWX memory. The same format
// used by Cobalt Strike's inline-execute and Sliver's BOF runner.
//
// # MITRE ATT&CK
//
//   - T1059 (Command and Scripting Interpreter) — in-memory code execution
//   - T1620 (Reflective Code Loading) — COFF loader is a textbook reflective primitive
//
// # Detection level
//
// moderate
//
// RWX memory allocation is visible to EDR; the payload never
// touches disk and runs inside the caller's process so there is
// no fresh-process telemetry. Behavioural EDRs that watch for
// `VirtualAlloc(RWX)` + `EXECUTE` from non-text regions flag
// the loader.
//
// # Example
//
// See [ExampleLoad] in bof_example_test.go.
//
// # See also
//
//   - docs/techniques/runtime/bof-loader.md
//   - [github.com/oioio-space/maldev/runtime/clr] — sibling reflective runtime (.NET)
//   - [github.com/oioio-space/maldev/inject] — alternative for cross-process delivery
//
// [github.com/oioio-space/maldev/runtime/clr]: https://pkg.go.dev/github.com/oioio-space/maldev/runtime/clr
// [github.com/oioio-space/maldev/inject]: https://pkg.go.dev/github.com/oioio-space/maldev/inject
package bof
