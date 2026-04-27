//go:build windows

// Package amsi disables the Antimalware Scan Interface in the current
// process via runtime memory patches on `amsi.dll`.
//
// AMSI is the Windows interface that ships scripts (.NET, PowerShell,
// VBScript, JavaScript) to a registered antimalware provider for
// scanning. PatchScanBuffer overwrites the prologue of `AmsiScanBuffer`
// with `xor eax,eax; ret` so the scan returns S_OK with a "clean"
// verdict regardless of input. PatchOpenSession flips the conditional
// jump in `AmsiOpenSession` so session creation always succeeds without
// initialising the provider. PatchAll applies both. ScanBufferPatch /
// OpenSessionPatch / All wrap each in an `evasion.Technique` for
// composition with `evasion.ApplyAll`.
//
// All entry points accept a `*wsyscall.Caller`. Pass `nil` to fall back
// to WinAPI for debugging; pass an indirect-syscall caller in
// production so the `NtProtectVirtualMemory` calls that flip the page
// to RWX are routed through clean ntdll stubs.
//
// # MITRE ATT&CK
//
//   - T1562.001 (Impair Defenses: Disable or Modify Tools)
//
// # Detection level
//
// noisy
//
// `NtProtectVirtualMemory` flips on `amsi.dll` are visible in ETW
// Threat Intelligence (`EVENT_TI_NTPROTECT`); the resulting
// `xor eax,eax; ret` byte pattern is detectable by memory scanners.
//
// # Example
//
// See [ExampleScanBufferPatch] in amsi_example_test.go.
//
// # See also
//
//   - docs/techniques/evasion/amsi-bypass.md
//   - [github.com/oioio-space/maldev/evasion/etw] — sibling defence-impair
//   - [github.com/oioio-space/maldev/evasion/unhook] — restore EDR-hooked APIs
//
// [github.com/oioio-space/maldev/evasion/etw]: https://pkg.go.dev/github.com/oioio-space/maldev/evasion/etw
// [github.com/oioio-space/maldev/evasion/unhook]: https://pkg.go.dev/github.com/oioio-space/maldev/evasion/unhook
package amsi
