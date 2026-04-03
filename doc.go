// Package maldev is a modular malware development library for offensive
// security research and red team operations.
//
// It provides composable building blocks organized in layers:
//
//   - Layer 0 (pure): [crypto], [encode], [hash], [random] — no OS interaction
//   - Layer 1 (OS): [win/api], [win/syscall], [win/ntapi], [win/token] — Windows primitives
//   - Layer 2 (tech): [evasion/*], [inject], [process], [pe], [cleanup] — offensive techniques
//   - Layer 3 (orch): [c2/transport], [c2/shell], [c2/meterpreter] — C2 infrastructure
//
// # Syscall Bypass
//
// All technique packages accept an optional *[win/syscall.Caller] parameter
// that routes NT function calls through direct or indirect syscalls,
// bypassing EDR user-mode hooks. Pass nil for standard WinAPI.
//
//	caller := wsyscall.New(wsyscall.MethodDirect, wsyscall.NewHellsGate())
//	amsi.PatchScanBuffer(caller)
//
// # Composable Evasion
//
// Evasion techniques implement the [evasion.Technique] interface and can be
// composed into slices for batch application:
//
//	techniques := preset.Stealth() // AMSI + ETW + unhook common functions
//	evasion.ApplyAll(techniques, caller)
//
// # MITRE ATT&CK
//
// Every technique package documents its MITRE ATT&CK mapping in its doc.go.
// See docs/mitre.md for the complete coverage table.
//
// This library is for authorized security research, red team operations,
// and penetration testing only.
package maldev
