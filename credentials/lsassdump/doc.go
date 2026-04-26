// Package lsassdump produces a MiniDump blob of lsass.exe's memory so
// downstream tooling (credentials/sekurlsa, mimikatz, pypykatz) can
// extract Windows credentials.
//
// Technique: Process memory dump of LSASS via NtReadVirtualMemory +
// handcrafted MiniDump stream. Does NOT call MiniDumpWriteDump (that
// export is heavily EDR-hooked); the MiniDump is assembled in-process.
//
// MITRE ATT&CK: T1003.001 (OS Credential Dumping: LSASS Memory)
// Platform: Windows (build / dump pipeline) — the on-disk PE-parsing
// helpers (Discover*Offset, DiscoverInitialSystemProcessRVA) are
// pure Go and run cross-platform so analysts can resolve EPROCESS
// offsets from a captured ntoskrnl.exe on Linux/CI.
//
// Detection: High — opening lsass.exe with PROCESS_VM_READ and
// reading the full address space is one of the loudest events any
// modern EDR watches. Reduce the blast radius by:
//
//   - Routing Nt* through a stealth *wsyscall.Caller (direct /
//     indirect syscall) — Open/Dump and FindLsassEProcess all
//     accept an optional Caller (nil = WinAPI fallback).
//   - Routing on-disk reads through a stealthopen.Opener
//     (Discover*Offset, FindLsassEProcess) so a path-based EDR
//     file-hook never sees the ntoskrnl.exe path.
//   - Writing the minidump to a non-standard path.
//
// PPL bypass via RTCore64 BYOVD: when lsass.exe runs with RunAsPPL=1
// (Win 11 default), userland NtOpenProcess(VM_READ) is denied
// regardless of token privileges. Unprotect/Reprotect zero the
// EPROCESS.Protection byte via a kernel/driver.ReadWriter (typically
// RTCore64) and restore it afterwards.
//
// EPROCESS-offset discovery (kvc-inspired, v0.31.x):
//
//   - DiscoverProtectionOffset(path, opener) — parses
//     PsIsProtectedProcess + PsIsProtectedProcessLight prologues,
//     cross-validates the disp32, returns EPROCESS.Protection's
//     byte offset. Cited in Unprotect/Reprotect when the operator
//     hasn't supplied a hand-curated PPLOffsetTable for the build.
//   - SignatureLevelOffset(prot) / SectionSignatureLevelOffset(prot)
//     — derived constants (Protection − 2 / Protection − 1).
//   - DiscoverUniqueProcessIdOffset(path, opener) — parses
//     PsGetProcessId's `mov rax, [rcx+disp32]` prologue.
//   - DiscoverActiveProcessLinksOffset(upidOff) — UniqueProcessId
//     + sizeof(HANDLE) on x64.
//   - DiscoverInitialSystemProcessRVA(path, opener) — RVA of the
//     PsInitialSystemProcess export inside ntoskrnl.exe.
//   - FindLsassEProcess(rw, lsassPID, opener, caller) — walks
//     PsActiveProcessLinks via the kernel ReadWriter and returns
//     the EPROCESS VA matching lsassPID; combines all of the above.
//
// All path-based discovery helpers accept a stealthopen.Opener
// (nil = os.Open) and resolve an empty path to
// `%SystemRoot%\System32\ntoskrnl.exe` via SHGetSpecialFolderPathW
// on Windows (recon/folder.Get(CSIDL_SYSTEM)).
package lsassdump
