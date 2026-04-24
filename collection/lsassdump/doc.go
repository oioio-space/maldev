// Package lsassdump produces a MiniDump blob of lsass.exe's memory so
// downstream tooling (mimikatz, pypykatz) can extract Windows credentials.
//
// Technique: Process memory dump of LSASS via NtReadVirtualMemory +
// handcrafted MiniDump stream. Does NOT call MiniDumpWriteDump (that
// export is heavily EDR-hooked); the MiniDump is assembled in-process.
//
// MITRE ATT&CK: T1003.001 (OS Credential Dumping: LSASS Memory)
// Platform: Windows
// Detection: High — opening lsass.exe with PROCESS_VM_READ and reading
// the full address space is one of the loudest events any modern EDR
// watches. Reduce the blast radius by routing reads through a stealth
// wsyscall.Caller (direct/indirect syscall) and writing the minidump
// to a non-standard path.
//
// Every public entry point accepts an optional *wsyscall.Caller. Passing
// nil falls back to the standard Nt* WinAPI calls.
package lsassdump
