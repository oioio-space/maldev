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
//
// How it works: Anti-debugging detects whether a debugger is attached to the
// current process, allowing the implant to alter its behavior or exit before
// an analyst can inspect it. On Windows, it checks the BeingDebugged flag in
// the Process Environment Block (PEB) via IsDebuggerPresent. On Linux, it
// reads /proc/self/status and checks whether TracerPid is non-zero, which
// indicates a ptrace-based debugger (like GDB or strace) is attached.
package antidebug
