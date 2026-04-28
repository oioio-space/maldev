// Package ntapi exposes a small set of typed Go wrappers over
// `ntdll!Nt*` functions that maldev components use frequently —
// memory allocation, write/protect, thread creation, and system
// information query.
//
// These wrappers go through the lazy `ntdll.dll` proc cache in
// [github.com/oioio-space/maldev/win/api]. They bypass kernel32 /
// kernelbase trampolines (which are hooked by most user-mode EDRs)
// but remain hookable at the ntdll boundary itself. For full
// userland-hook bypass, use [github.com/oioio-space/maldev/win/syscall]
// with `MethodDirect` or `MethodIndirect` — that path skips ntdll
// stubs entirely by reading SSNs and issuing the `syscall`
// instruction in-process.
//
// Wrapped surface:
//
//   - [NtAllocateVirtualMemory] — RWX allocation primitive.
//   - [NtWriteVirtualMemory] — local or remote write.
//   - [NtProtectVirtualMemory] — page protection flip (RW → RX).
//   - [NtCreateThreadEx] — thread creation with hide-from-debugger flag.
//   - [NtQuerySystemInformation] — system-wide enumeration.
//
// # MITRE ATT&CK
//
//   - T1106 (Native API) — direct ntdll invocation
//
// # Detection level
//
// quiet
//
// Calling `ntdll.dll` exports is the lowest-level supported user-mode
// path on Windows; ntdll-hook EDRs (Defender, ESET, Sentinel) still
// see these calls. The signal drops to very-quiet only when callers
// move to direct/indirect syscalls in win/syscall.
//
// # Example
//
// See [ExampleNtAllocateVirtualMemory] in ntapi_example_test.go.
//
// # See also
//
//   - docs/techniques/syscalls/README.md
//   - [github.com/oioio-space/maldev/win/syscall] — direct/indirect SSN syscalls
//   - [github.com/oioio-space/maldev/win/api] — hash-resolved imports + lazy DLL handles
//
// [github.com/oioio-space/maldev/win/syscall]: https://pkg.go.dev/github.com/oioio-space/maldev/win/syscall
// [github.com/oioio-space/maldev/win/api]: https://pkg.go.dev/github.com/oioio-space/maldev/win/api
package ntapi
