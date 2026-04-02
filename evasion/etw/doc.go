// Package etw provides ETW (Event Tracing for Windows) bypass techniques
// through runtime patching of ntdll event writing functions.
//
// Technique: Runtime patching of ntdll ETW event writing functions.
// MITRE ATT&CK: T1562.001 (Impair Defenses: Disable or Modify Tools)
// Platform: Windows
// Detection: Medium -- patches ntdll.dll in-memory, detectable by integrity checks.
//
// Patch overwrites all 5 ETW event writing functions (EtwEventWrite,
// EtwEventWriteEx, EtwEventWriteFull, EtwEventWriteString, EtwEventWriteTransfer)
// with "xor rax, rax; ret" (48 33 C0 C3), making them return STATUS_SUCCESS
// without logging.
//
// PatchNtTraceEvent patches the lower-level NtTraceEvent with a single RET.
//
// How it works: ETW is the primary telemetry pipeline in Windows, used by EDR
// and security products to receive real-time events from both user-mode and
// kernel-mode providers. By patching the ETW event writing functions in the
// process's own copy of ntdll.dll, the implant prevents any ETW events from
// being emitted from its process. The patch replaces each function's prologue
// with "xor rax, rax; ret", which returns STATUS_SUCCESS (0) without writing
// any event data, effectively blinding any ETW consumer monitoring the process.
package etw
