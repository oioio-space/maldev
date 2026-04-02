// Package inject provides unified shellcode injection techniques
// for Windows and Linux platforms with automatic fallback support.
//
// Technique: Process injection via multiple methods per platform.
// MITRE ATT&CK: T1055 (Process Injection)
// Platform: Cross-platform (Windows and Linux)
// Detection: High -- all injection methods are monitored by EDR products.
//
// Windows methods:
//   - CreateRemoteThread (crt): classic remote thread injection
//   - CreateThread (ct): self-injection with XOR evasion and NtCreateThreadEx
//   - QueueUserAPC (apc): APC injection into existing thread
//   - EarlyBirdAPC (earlybird): APC injection into suspended child process
//   - ProcessHollowing (hollow): replace suspended process thread context
//   - RtlCreateUserThread (rtl): undocumented ntdll thread creation
//   - DirectSyscall (syscall): bypass EDR hooks with raw syscall stubs
//   - CreateFiber (fiber): fiber-based shellcode execution
//
// Linux methods:
//   - Ptrace (ptrace): inject via ptrace attach
//   - MemFD (memfd): execute via memfd_create anonymous file
//   - ProcMem (procmem): write to /proc/self/mem
//
// The InjectWithFallback function tries alternate methods if the primary fails.
package inject
