// Package evasion defines the Technique interface and shared primitives used
// by the sub-packages to bypass defensive software (AMSI, ETW, inline hooks,
// sandbox/debugger/VM checks).
//
// Technique: Composer. Individual techniques live in sub-packages;
// evasion itself defines the contract (Technique + ApplyAll + Caller erasure)
// plus the preset/ composer for pre-validated bundles.
// MITRE ATT&CK: T1562.001 (Impair Defenses), T1497 (Virtualization/Sandbox
// Evasion), T1622 (Debugger Evasion), T1574.012 (Inline Hook Subversion)
// Platform: Cross-platform interface; most sub-packages Windows-only.
// Detection: Per sub-package.
//
// Sub-packages (see each doc.go for MITRE + detection level):
//
//   - acg, amsi, antidebug, antivm, blockdlls, cet, etw, fakecmd,
//     herpaderping, hideprocess, hook, hook/bridge, hook/shellcode, hwbp,
//     phant0m, preset, sandbox, sleepmask, stealthopen, timing, unhook
//
// Technique contract:
//
//	type Technique interface {
//	    Name() string
//	    Apply(c Caller) error
//	}
//
// Caller is an interface{} placeholder to avoid importing win/syscall from
// this cross-platform package; Windows callers pass *wsyscall.Caller (may be
// nil to use standard WinAPI).
package evasion
