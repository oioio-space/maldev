// Package sekurlsa extracts credential material from a Windows LSASS
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
// Scope:
//   - MSV1_0 NTLM hashes (NT / LM / SHA1) — v0.23.x
//   - Wdigest plaintext passwords — v0.24.x
//   - DPAPI master-key cache — v0.25.x
//   - TSPkg (Terminal Services / RDP) plaintext — v0.26.0
//   - Kerberos password + tickets — v0.26.1
//   - CredMan / Vault — v0.27.x (framework; per-node layout opt-in)
//   - CloudAP (Azure AD PRT) + LiveSSP — v0.28.x (framework;
//     per-build layouts opt-in)
// WoW64 / x86 dumps are detected and rejected with
// ErrUnsupportedArchitecture in v0.29.0+ — the parser only ships
// x64 walkers. Implementing x86 would require a parallel set of
// layouts with 4-byte pointers and 8-byte UNICODE_STRINGs; modern
// Win 10/11 lsass is x64 by default so the operational value is
// limited.
//
// Real-binary validation findings (v0.30.0, vs Win 10 22H2 build
// 19045 dump):
//
//   - MSV1_0 NTLM hashes: validated end-to-end (interactive user's
//     NT hash round-trips through Parse).
//   - Wdigest: signature matches; cache empty as expected
//     (UseLogonCredential=0 default).
//   - DPAPI master keys: signature lives in dpapisrv.dll (NOT
//     lsasrv.dll). Parse() now falls back to dpapisrv when the
//     lsasrv scan misses — first cache-population path validated.
//   - Kerberos: signature matches in kerberos.dll, but the v0.26.1
//     walker uses a flat doubly-linked list and Vista+ Kerberos
//     uses an RTL_AVL_TABLE instead — walker returns zero sessions
//     silently. AVL refactor queued for v0.30.x.
//   - TSPkg: KvcForensic signature `48 83 EC 20 48 8B 0D` doesn't
//     match in tspkg.dll on build 19045. Same AVL-tree caveat as
//     Kerberos applies once the signature lands.
//
// Out of scope today: WoW64 (x86) extraction, live-process attach,
// RTL_AVL_TABLE walker for Kerberos + TSPkg sessions on Vista+
// (v0.30.x follow-up).
//
// Each provider auto-disables when its Layout.NodeSize is zero — the
// walker is skipped at no runtime cost. The v0.25.2+ default
// templates ship every signature + layout from KvcForensic's
// validated JSON corpus, so all four providers run by default on a
// covered build.
//
// DPAPI master keys are stored pre-decrypted in lsasrv.dll's
// g_MasterKeyCacheList; the walker reads them as-is and grafts them
// onto MSV LogonSessions by LUID. Operators downstream feed the key
// bytes to BCryptDecrypt to unwrap Chrome cookies, Vault credentials,
// WinRM saved sessions, and other DPAPI-protected blobs.
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
package sekurlsa
