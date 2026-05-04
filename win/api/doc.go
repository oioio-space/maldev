//go:build windows

// Package api is the single source of truth for Windows DLL handles,
// procedure references, and structures shared across maldev. Also
// implements the PEB-walk + ROR13 export-hash primitive used by every
// downstream package that needs string-free import resolution.
//
// All other maldev modules import DLL handles and lazy procs from
// here instead of declaring their own [windows.LazyDLL] instances.
// This prevents duplicate handles, ensures every system DLL is
// resolved through [windows.NewLazySystemDLL] (System32-only search
// path — defeats DLL planting in CWD), and gives a single audit
// surface for the library's import footprint.
//
// Exported handles: Kernel32, Ntdll, Advapi32, User32, Shell32,
// Userenv, Netapi32 — populated lazily on first reference, never
// reloaded.
//
// API hashing — [ResolveByHash] walks the PEB
// `InLoadOrderModuleList` to find a loaded DLL by ROR13 hash, then
// scans its export directory to find a function by ROR13 hash. The
// resulting `uintptr` is the in-process address of the export, with
// no plaintext API name in the binary. Pre-computed constants for
// common modules and APIs (HashKernel32, HashLoadLibraryA,
// HashNtAllocateVirtualMemory, …) ship in `resolve_windows.go`.
//
// # MITRE ATT&CK
//
//   - T1106 (Native API) — direct Windows API invocation, including
//     hash-resolved imports
//   - T1027 (Obfuscated Files or Information) — string-free import
//     resolution via export hashing
//
// # Detection level
//
// very-quiet
//
// Loading System32 DLLs is normal process behaviour; PEB walk + export
// table read are user-mode-readable memory. No syscall, no telemetry
// trail.
//
// # Required privileges
//
// unprivileged. Loading System32 DLLs is a per-process
// operation; PEB walk reads user-mode-readable memory; export
// table is read from the on-image file mapping every process
// already holds. No syscall privilege gate, no token bump.
//
// # Platform
//
// Windows-only (`//go:build windows`). The PEB layout, ROR13
// hash convention, and `windows.LazyDLL` machinery are
// Windows-specific.
//
// # Example
//
// See [ExampleResolveByHash] and [ExamplePatchProc] in api_example_test.go.
//
// # See also
//
//   - docs/techniques/syscalls/api-hashing.md
//   - [github.com/oioio-space/maldev/win/syscall] — direct/indirect SSN syscalls layered on top
//   - [github.com/oioio-space/maldev/win/ntapi] — typed wrappers around the resolved exports
//
// [github.com/oioio-space/maldev/win/syscall]: https://pkg.go.dev/github.com/oioio-space/maldev/win/syscall
// [github.com/oioio-space/maldev/win/ntapi]: https://pkg.go.dev/github.com/oioio-space/maldev/win/ntapi
package api
