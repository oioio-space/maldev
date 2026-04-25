// Package lsasparse extracts credential material from a Windows LSASS
// minidump — the consumer counterpart to credentials/lsassdump.
//
// Technique: parse a MINIDUMP blob, locate lsasrv.dll / msv1_0.dll in
// the captured module list, scan for the LSA initialization-vector +
// session-key globals via per-build byte-pattern templates, decrypt
// the MSV1_0 logon-session list, and surface NTLM hash pairs for
// every session whose primary credentials decrypt cleanly.
//
// MITRE ATT&CK: T1003.001 (OS Credential Dumping: LSASS Memory).
// Platform: cross-platform (pure Go) — analysts can parse a dump from
// any host, not just Windows. The package never opens lsass.exe
// itself; that's credentials/lsassdump's job.
//
// Detection: Low. The LOUD operations are the dump itself (PROCESS_VM_READ
// + NtReadVirtualMemory loop, covered by docs/techniques/collection/lsass-dump.md)
// and any optional driver-assisted PPL bypass. Parsing happens in the
// implant's own address space with pure-Go primitives — no further
// detection surface.
//
// v1 scope: MSV1_0 NTLM hash extraction (NT/LM/SHA1) for every active
// logon session. Out of scope: WDigest plaintext, Kerberos tickets,
// DPAPI master keys, LiveSSP / TSPkg / CloudAP secrets, live-process
// attach. Each is a follow-up chantier on top of the v1 crypto layer.
//
// Templates ship inline for Win10 19H1 → 22H2 (builds 18362–19045)
// and Win11 21H2 → 22H2 pre-22622 (builds 22000–22621). A dump from
// any of those builds parses out of the box — no operator setup. See
// default_templates.go for the canonical set; pypykatz (GPL-3) and
// mimikatz (CC-BY-NC-SA) are the published research sources for the
// byte patterns + offsets, which are facts about Microsoft binaries
// rather than copyrightable expression.
//
// Other builds return ErrUnsupportedBuild from Parse — operators
// register additional templates via RegisterTemplate at runtime.
//
// Layering: Layer 2 alongside credentials/lsassdump. Pure Go; no
// dependency on win/api or kernel/driver.
package lsasparse
