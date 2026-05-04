// Package memory provides secure memory cleanup primitives for wiping
// sensitive data (shellcode, keys, credentials) from process memory.
//
// Three primitives:
//
//   - SecureZero overwrites a byte slice with zeros using Go's `clear`
//     builtin, which the compiler treats as an intrinsic and never elides
//     as a dead store.
//   - WipeAndFree (Windows) changes the page protection of a VirtualAlloc'd
//     region to RW, writes zeros across it, then releases the pages via
//     VirtualFree.
//   - DoSecret wraps a function call and, when built with Go 1.26+ and
//     GOEXPERIMENT=runtimesecret, erases the registers, stack, and heap
//     temporaries used by that call. On other builds it is a plain call
//     with no erasure, so callers may wrap sensitive computations
//     unconditionally.
//
// # Build matrix
//
//	Feature      | Min Go | Extra                       | Platforms
//	-------------|--------|-----------------------------|----------------------
//	SecureZero   | 1.21   | -                           | all
//	WipeAndFree  | 1.21   | -                           | windows
//	DoSecret     | 1.21   | stub (no erasure)           | all
//	DoSecret     | 1.26   | GOEXPERIMENT=runtimesecret  | linux/amd64+arm64
//
// # MITRE ATT&CK
//
//   - T1070 (Indicator Removal)
//
// # Detection level
//
// very-quiet
//
// VirtualProtect + VirtualFree are high-volume legitimate calls with no
// distinctive pattern.
//
// # Required privileges
//
// unprivileged. All three primitives operate on the calling
// process's own memory: `SecureZero` is a pure-Go intrinsic;
// `WipeAndFree` calls `VirtualProtect` + `VirtualFree` against
// pages the process itself allocated; `DoSecret` runs entirely
// in Go-managed memory. No special privilege, no token bump,
// no remote handle.
//
// # Platform
//
// `SecureZero` and `DoSecret` are cross-platform.
// `WipeAndFree` is Windows-only (`VirtualAlloc` lifecycle).
// `DoSecret` only erases registers/stack/heap when built with
// Go 1.26+ and `GOEXPERIMENT=runtimesecret` (linux/amd64+arm64
// today); on every other build it is a plain call so callers
// may wrap unconditionally.
//
// # Example
//
// See [ExampleSecureZero] and [ExampleWipeAndFree] in memory_example_test.go.
//
// # See also
//
//   - docs/techniques/cleanup/memory-wipe.md
package memory
