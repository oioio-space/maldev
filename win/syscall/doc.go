// Package syscall provides multiple strategies for invoking Windows NT syscalls,
// from standard WinAPI calls through kernel32 to stealthy direct/indirect
// syscall techniques that bypass userland hooks.
//
// Technique: System call invocation via Hell's Gate, Halo's Gate, and
// Tartarus Gate SSN resolvers with direct and indirect stub execution.
// MITRE ATT&CK: T1106 (Native API)
// Detection: Low (indirect) to Medium (direct) — direct syscalls are
// detectable by memory scanners; indirect syscalls defeat call-stack analysis.
//
// # Methods
//
//   - MethodWinAPI: standard kernel32/advapi32 (hookable)
//   - MethodNativeAPI: ntdll NtXxx (bypass kernel32 hooks)
//   - MethodDirect: in-process syscall stub (bypass all userland hooks)
//   - MethodIndirect: syscall;ret gadget in ntdll (most stealthy)
//
// # SSN Resolvers
//
//   - HellsGate: read SSN from unhooked ntdll prologue
//   - HalosGate: scan neighboring stubs when target is hooked
//   - TartarusGate: follow JMP hooks to extract SSN from trampoline
//   - Chain: try multiple resolvers in sequence
//
// Platform: Windows only.
package syscall
