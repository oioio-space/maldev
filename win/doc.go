//go:build windows

// Package win is the parent umbrella for Windows-only primitives.
//
// Technique: Windows API invocation primitives -- DLL handle caching, PEB
// walk + ROR13 export hashing, typed NtXxx wrappers, SSN resolvers, token
// and privilege operations, version detection, domain status.
// MITRE ATT&CK: T1106 (Native API), T1134 (Access Token Manipulation),
// T1082 (System Information Discovery).
// Platform: Windows
// Detection: Low per-primitive; attacks compose these into higher-level
// techniques.
//
// Sub-packages:
//
//   - win/api:         DLL handles + PEB walk export resolution by ROR13 hash
//   - win/ntapi:       typed NtXxx wrappers (T1106)
//   - win/syscall:     direct/indirect syscalls via HellsGate family
//   - win/token:       token theft, impersonation, privilege enable (T1134)
//   - win/privilege:   elevation checks and RunAs helpers
//   - win/impersonate: thread-level impersonation + GetSystem/GetTI
//   - win/user:        local user account management via NetAPI32 (T1136.001)
//   - win/version:     OS version + UBR detection (T1082)
//   - win/domain:      domain join status enumeration (T1082)
//
// Import the sub-package for the specific primitive needed. The parent
// package exports nothing.
package win
