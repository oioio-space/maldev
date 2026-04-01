// Package timing provides time-based evasion techniques that defeat sandbox
// analysis systems which fast-forward Sleep() calls.
//
// Technique: CPU-burning delays that bypass hooked sleep functions.
// MITRE ATT&CK: T1497.003 (Virtualization/Sandbox Evasion: Time Based Evasion)
// Platform: Cross-platform
// Detection: Low -- CPU usage spikes are not typically alerted on.
//
// Two methods:
//   - BusyWait: burns CPU for a specified duration using time comparison
//   - BusyWaitPrimality: burns CPU via primality testing (harder to detect pattern)
package timing
