//go:build windows

// Package etw blinds Event Tracing for Windows in the current process
// by patching the ETW write helpers in `ntdll.dll` with
// `xor rax,rax; ret`.
//
// PatchAll overwrites all five user-mode write functions
// (`EtwEventWrite`, `EtwEventWriteEx`, `EtwEventWriteFull`,
// `EtwEventWriteString`, `EtwEventWriteTransfer`) so any provider in
// the process emits zero events while still returning STATUS_SUCCESS.
// PatchNtTraceEvent additionally patches the kernel-call layer
// `NtTraceEvent` with a single RET — useful when an EDR is direct-
// calling that primitive. Wrappers `All` / `PatchTechnique` /
// `NtTraceTechnique` adapt these to `evasion.Technique` for use with
// `evasion.ApplyAll`.
//
// All entry points accept a `*wsyscall.Caller`. Pass an indirect-
// syscall caller in production so the `NtProtectVirtualMemory` flips
// route through clean ntdll stubs even if the EDR has hooked them.
//
// # MITRE ATT&CK
//
//   - T1562.001 (Impair Defenses: Disable or Modify Tools)
//
// # Detection level
//
// moderate
//
// The patched bytes are visible to anyone reading `ntdll.dll` RX pages
// from outside; integrity-checking EDR stages catch this. The
// `NtProtectVirtualMemory` calls show up in TI ETW events.
//
// # Example
//
// See [ExamplePatchAll] in etw_example_test.go.
//
// # See also
//
//   - docs/techniques/evasion/etw-patching.md
//   - [github.com/oioio-space/maldev/evasion/amsi] — sibling defence-impair
//
// [github.com/oioio-space/maldev/evasion/amsi]: https://pkg.go.dev/github.com/oioio-space/maldev/evasion/amsi
package etw
