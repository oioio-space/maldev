// Package samdump performs offline NT-hash extraction from a SAM
// hive (with the SYSTEM hive supplying the boot key). It is the
// pure-Go equivalent of impacket's `secretsdump.py LOCAL` mode and
// the SYSTEM/SAM half of mimikatz `lsadump::sam`.
//
// MITRE ATT&CK: T1003.002 — OS Credential Dumping: Security Account
// Manager.
//
// Platform: cross-platform (pure Go) for the offline Dump path;
// LiveDump is Windows-only (shells out to reg.exe save).
//
// Detection level: HIGH for LiveDump (reg.exe save HKLM\SAM is one
// of the loudest credential-dumping signals an EDR can watch — the
// queued NtSaveKey path under win/ntapi will lower this); LOW once
// the operator has the hive bytes in hand (this package is pure-Go
// cell parsing + AES/RC4 + DES math, no syscalls).
//
// Workflow:
//
//   1. Operator stages SYSTEM + SAM hive files (offline copies via
//      `reg save`, VSS shadow copy, NTFS raw read, or any other
//      acquisition technique). The recon/shadowcopy package handles
//      live-hive acquisition on Windows.
//   2. Call samdump.Dump(systemReader, samReader) — pure-Go, no
//      OS calls. Returns []Account with username + RID + LM/NT
//      hashes, plus computed pwdump/secretsdump output lines.
//
// Algorithm — clean-room from impacket secretsdump.py + Microsoft
// MS-RegFile + SharpKatz Sam.cs reference (none vendored):
//
//   1. SYSTEM hive → walk Policy\\PolEKList → AES-256 LSA key.
//   2. SYSTEM hive → walk Lsa\\{JD,Skew1,GBG,Data} → 16 raw bytes,
//      permuted into the boot key (syskey).
//   3. SAM hive → SAM\\Domains\\Account\\F → header + AES-encrypted
//      hashed-bootkey blob; decrypt with AES-128-CBC keyed on
//      MD5(bootKey || rid_str || qwerty || rid_str). The result
//      is the per-domain "hashed bootkey" used as the per-user RC4
//      / AES key.
//   4. SAM hive → SAM\\Domains\\Account\\Users\\<RID> → F (account
//      flags + LM/NT history) + V (username + LM/NT current).
//   5. For each user: derive per-user keys from hashed bootkey + RID,
//      decrypt LM hash + NT hash (DES legacy or AES-128-CBC modern,
//      Win10 1607+).
package samdump
