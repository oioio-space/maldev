// Package ntapi provides typed Go wrappers for Native API functions (ntdll.dll).
//
// These wrappers call through ntdll directly, bypassing kernel32.dll hooks.
// They are still hookable at the ntdll level — for full hook bypass, use
// win/syscall with MethodDirect or MethodIndirect.
//
// Technique: Native API invocation via ntdll.dll.
// MITRE ATT&CK: T1106 (Native API)
// Detection: Low — calling ntdll functions directly is normal Windows behavior.
//
// Wrapped functions:
//
//   - NtAllocateVirtualMemory
//   - NtWriteVirtualMemory
//   - NtProtectVirtualMemory
//   - NtCreateThreadEx
//   - NtQuerySystemInformation
//
// Platform: Windows only.
package ntapi
