// Package shellcode provides pre-fabricated x64 shellcode templates for
// use as handlers in RemoteInstall.
//
// Technique: Position-independent x64 shellcode with values patched at runtime.
// MITRE ATT&CK: T1574.012 — Hijack Execution Flow: Inline Hooking.
// Platform: Windows (x64).
// Detection: High.
//
// Example:
//
//	sc := shellcode.Block() // shellcode that returns 0
package shellcode
