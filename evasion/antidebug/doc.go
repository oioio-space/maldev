// Package antidebug provides cross-platform debugger detection techniques.
//
// Technique: Debugger presence detection via OS-specific APIs.
// MITRE ATT&CK: T1622 (Debugger Evasion)
// Platform: Cross-platform (Windows and Linux)
// Detection: Low -- checking for debuggers is common in legitimate software.
//
// Platform-specific implementations:
//   - Windows: calls IsDebuggerPresent from kernel32.dll
//   - Linux: reads TracerPid from /proc/self/status
package antidebug
