// Package unhook provides techniques to remove EDR/AV hooks from ntdll.dll
// by restoring original function bytes from a clean copy.
//
// Technique: Restore original ntdll.dll function bytes from disk or child process.
// MITRE ATT&CK: T1562.001 (Impair Defenses: Disable or Modify Tools)
// Platform: Windows
// Detection: High -- reading ntdll from disk or spawning processes is monitored.
//
// Three methods by increasing sophistication:
//   - ClassicUnhook: restore first 5 bytes of a single function from a disk copy
//   - FullUnhook: replace the entire .text section from a disk copy, removing ALL hooks
//   - PerunUnhook: read pristine ntdll from a freshly spawned suspended child process
package unhook
