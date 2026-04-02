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
//
// How it works: EDR products install inline hooks by overwriting the first few
// bytes of key ntdll functions (like NtAllocateVirtualMemory) with a JMP
// instruction that redirects execution into the EDR's monitoring DLL. This
// lets the EDR inspect every syscall before it reaches the kernel. Unhooking
// reverses this by obtaining a clean, unmodified copy of ntdll.dll -- either
// from disk or from a freshly spawned process that has not yet been hooked --
// and overwriting the hooked .text section with the original bytes, restoring
// all functions to their pristine state.
package unhook
