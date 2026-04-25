package sekurlsa

// Built-in Templates spanning every NT6+ x64 Windows build for which
// MSV / Wdigest / DPAPI signatures and offsets are publicly
// documented — Win 7 RTM / Server 2008 R2 (build 7600) through
// Win 11 25H2 / Server 2025 (build 26200+).
//
// The values are *facts* about Microsoft's compiled lsasrv.dll —
// byte signatures present in the binary, offset distances between
// instruction sequences, and field positions inside Microsoft data
// structures. Facts are not copyrightable (Feist v. Rural). The code
// that uses them is an independent re-implementation in Go.
//
// Research sources — every credential-extraction tool reuses these
// patterns because they are empirical observations:
//
//   - KvcForensic (MIT, Marek Wesołowski / wesmar) —
//       https://github.com/wesmar/KvcForensic
//       The 10-range MSV signature breakdown plus the Wdigest /
//       DPAPI / LSA-24H2 patterns ship as `KvcForensic.json`; we
//       cite them directly because the upstream license is
//       MIT-compatible with maldev.
//   - pypykatz (GPL-3, Skelsec) —
//       pypykatz/lsadecryptor/lsa_template_nt6.py
//       pypykatz/lsadecryptor/packages/msv/templates.py
//       Used as cross-reference for the older LSA crypto offsets
//       (pre-24H2) and the KIWI_MSV1_0_LIST_NN layout offsets.
//   - mimikatz (CC-BY-NC-SA, Benjamin Delpy "gentilkiwi") —
//       mimikatz/modules/sekurlsa/kuhl_m_sekurlsa_*.c
//       Original research; not vendored.
//
// We do not vendor or translate any project's source code; only the
// documented byte values are carried into our Template structs.
// maldev itself remains MIT.
//
// Validation status per layout:
//
//   ★ "VM-validated" — a real lsass.exe dump from that build round-tripped
//     through Parse() with the canonical pypykatz / KvcForensic JSON.
//     None yet — real-binary validation is queued for when local VM
//     dumps are generated.
//
//   ◎ "research-validated" — values transcribed from KvcForensic's
//     parser_support: true ranges (Win 11 24H2+) or pypykatz's
//     published templates. Framework correctness verified via
//     synthetic fixtures.
//
//   ▲ "best-effort" — older-build per-field offsets where KvcForensic
//     ships parser_support: false (signature only, layout zeros).
//     pypykatz's KIWI_MSV1_0_LIST_NN values are the best
//     publicly-available source; ±8-byte tweaks per LCU possible.
//
// Operators on a build whose values produce a warning register an
// additional Template via RegisterTemplate at runtime — sorted
// ascending by BuildMin, the lookup picks the first covering match
// so an operator's narrower range overrides a built-in.

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

// ===== LSA crypto signature ==========================================
//
// The same 16-byte signature works from Win 8.1 (build 9600) through
// Win 11 25H2 / Server 2025. The IV / 3DES / AES rel32 offsets shift
// between the v0.23.x baseline (Win 10 1903 → Win 11 22H2 pre-22622:
// IV +0x43) and Win 11 24H2+ (IV +0x47). KvcForensic's JSON ships
// the 24H2+ offsets; pypykatz documents the older ones. Older builds
// (Win 7 SP1, Win 8) use different signatures and are below.

// lsaSignatureCommon — `LsaInitializeProtectedMemory` prologue.
// Stable byte sequence across Win 8.1 → Win 11 25H2.
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

// lsaSignatureWin7Sp1 — Win 7 SP1 / Server 2008 R2 (build 7601).
// pypykatz template `LSADecryptorTemplate_x64_NT6_1_7601`.
var lsaSignatureWin7Sp1 = []byte{
	0x48, 0x83, 0xEC, 0x30,
	0x48, 0x8B, 0x05,
	0x00, 0x00, 0x00, // wildcards 7-9 (the rel32)
}
var lsaWildcardsWin7Sp1 = []int{7, 8, 9}

// lsaSignatureWin8 — Win 8 / Server 2012 (build 9200).
// pypykatz template `LSADecryptorTemplate_x64_NT6_2_9200`.
var lsaSignatureWin8 = []byte{
	0x48, 0x8D, 0x4D, 0xD8,
	0x48, 0x8B, 0x05,
}

// ===== MSV1_0 LogonSessionList signatures (per KvcForensic) ==========
//
// KvcForensic's JSON ships nine MSV signature ranges. Each range's
// byte sequence is reproduced verbatim here (research credit, no
// source code reused). The variable naming uses descriptive
// build-family suffixes; the canonical KvcForensic name for each
// is documented in the comment.

// msvSignatureWin7 — KvcForensic `MSV_x64_61` (builds 7600-9199).
var msvSignatureWin7 = []byte{
	0x33, 0xF6, 0x45, 0x89, 0x2F,
	0x4C, 0x8B, 0xF3,
	0x85, 0xFF,
	0x0F, 0x84,
}

// msvSignatureWin8 — KvcForensic `MSV_x64_62` (builds 9200-9599).
// Same bytes also seen on Win 10 1507-1607 (`MSV_x64_10_1507_1607`)
// and Win 10 1803-22H2 / Server 2019 (`MSV_x64_1803_22H2`).
var msvSignatureWin8 = []byte{
	0x33, 0xFF, 0x41, 0x89, 0x37,
	0x4C, 0x8B, 0xF3,
	0x45, 0x85, 0xC0,
	0x74,
}

// msvSignatureWin81 — KvcForensic `MSV_x64_63` (builds 9600-10239).
// Distinct 13-byte signature for Win 8.1 / Server 2012 R2.
var msvSignatureWin81 = []byte{
	0x8B, 0xDE,
	0x48, 0x8D, 0x0C, 0x5B,
	0x48, 0xC1, 0xE1, 0x05,
	0x48, 0x8D, 0x05,
}

// msvSignatureWin10Cu — KvcForensic `MSV_x64_1703` (builds
// 15063-17133). Win 10 Creators Update / Fall Creators Update.
var msvSignatureWin10Cu = []byte{
	0x33, 0xFF, 0x45, 0x89, 0x37,
	0x48, 0x8B, 0xF3,
	0x45, 0x85, 0xC9,
	0x74,
}

// msvSignatureWin11Rtm — KvcForensic `MSV_x64_11_2022` (builds
// 20348-22099). Server 2022 + Win 11 21H2.
var msvSignatureWin11Rtm = []byte{
	0x45, 0x89, 0x34, 0x24,
	0x4C, 0x8B, 0xFF,
	0x8B, 0xF3,
	0x45, 0x85, 0xC0,
	0x74,
}

// msvSignatureWin11_22H2 — KvcForensic `MSV_x64_11_2023` (builds
// 22100-26099). Win 11 22H2 / 23H2.
var msvSignatureWin1122H2 = []byte{
	0x45, 0x89, 0x37,
	0x4C, 0x8B, 0xF7,
	0x8B, 0xF3,
	0x45, 0x85, 0xC0,
	0x0F,
}

// msvSignatureWin1124H2 — KvcForensic `MSV_x64_11_24H2` (builds
// 26100+). Win 11 24H2 / 25H2 / Server 2025.
var msvSignatureWin1124H2 = []byte{
	0x45, 0x89, 0x34, 0x24,
	0x8B, 0xFB,
	0x45, 0x85, 0xC0,
	0x0F,
}

// ===== MSV1_0 _MSV1_0_LOGON_SESSION layouts =========================
//
// Field offsets are byte distances from the start of the node. Each
// layout corresponds to a KIWI_MSV1_0_LIST_NN class in pypykatz.
// NodeSize is the smallest size that covers every offset we read,
// not the full Microsoft struct (Microsoft has freely appended
// fields across builds).
//
// Only the LIST_65 (Win 11 24H2+) layout has KvcForensic
// parser_support: true validation. Older layouts are pypykatz
// research-cited (◎) or best-effort (▲).

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

// msvLayoutKiwiList63 — Win 10 1803 – 22H2 + Server 2019 (builds
// 17134 – 20347). ◎
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

// msvLayoutKiwiList64 — Server 2022 / Win 11 21H2-23H2 (builds
// 20348 – 26099). ◎
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

// msvLayoutKiwiList65 — Win 11 24H2 / 25H2 / Server 2025 (builds
// 26100+). ◎ KvcForensic parser_support: true — these offsets ship
// in `KvcForensic.json` and are exercised by KvcForensic's parser on
// real binaries.
var msvLayoutKiwiList65 = MSVLayout{
	NodeSize:          0x180, // covers fields up to CredentialsOffset+8
	LUIDOffset:        0x70,  // KvcForensic session_luid_offset = 112
	UserNameOffset:    0xA0,  // KvcForensic session_username_offset = 160
	LogonDomainOffset: 0xB0,  // KvcForensic session_domain_offset = 176
	LogonServerOffset: 0xF8,  // not in KvcForensic; pypykatz best-effort
	LogonTypeOffset:   0xD8,  // pypykatz best-effort
	LogonTimeOffset:   0xF0,  // pypykatz best-effort
	SIDOffset:         0xE0,  // KvcForensic session_sid_ptr_offset = 224
	CredentialsOffset: 0x118, // KvcForensic session_credentials_ptr_offset = 280
}

// ===== Wdigest signatures (per KvcForensic) =========================

// wdigestSignaturePre11 — KvcForensic `WDigest_x64_pre11`
// (builds 6000-21999). 4-byte sig, rel32 at match-4.
var wdigestSignaturePre11 = []byte{0x48, 0x3B, 0xD9, 0x74}

// wdigestSignatureWin11Plus — KvcForensic `WDigest_x64_11plus`
// (builds 22000+). Longer sig for the reshuffled prologue.
var wdigestSignatureWin11Plus = []byte{
	0x48, 0x3B, 0xC6,
	0x74, 0x11,
	0x8B, 0x4B, 0x20,
	0x39, 0x48,
}

// wdigestLayoutCommon — KIWI_WDIGEST_LIST_ENTRY layout.
// NodeSize/per-field offsets transcribed from pypykatz; KvcForensic
// only ships first_entry_offset and primary_offset (= our
// PasswordOffset, 48 = 0x30 — different from pypykatz's 0x58).
// Operators with verified field offsets register an extended
// Template at init.
var wdigestLayoutCommon = WdigestLayout{
	NodeSize:       0x80,
	LUIDOffset:     0x28,
	UserNameOffset: 0x38,
	DomainOffset:   0x48,
	PasswordOffset: 0x58,
}

// ===== DPAPI signature (per KvcForensic) ============================

// dpapiSignatureWin10Plus — KvcForensic `Dpapi_x64_win10_plus`
// (builds 14393+). Win 10 1607 / Server 2016 onward.
var dpapiSignatureWin10Plus = []byte{
	0x48, 0x89, 0x4F, 0x08,
	0x48, 0x89, 0x78, 0x08,
}

// dpapiLayoutCommon — KIWI_MASTERKEY_CACHE_ENTRY layout. KvcForensic
// doesn't break out the per-field offsets in its JSON; pypykatz
// research-cited values are the best-effort baseline.
var dpapiLayoutCommon = DPAPILayout{
	NodeSize:       0x80,
	LUIDOffset:     0x10,
	KeyGUIDOffset:  0x18,
	KeySizeOffset:  0x28,
	KeyBytesOffset: 0x30,
}

// ===== TSPkg signature + layout (per KvcForensic) ====================

// tspkgSignatureCommon — KvcForensic `Tspkg_x64_vista_to_win10` and
// `Tspkg_x64_win11_24h2_plus` both ship the same 7-byte signature
// `48 83 EC 20 48 8B 0D` (sub rsp, 20h; mov rcx, [rip+rel32]) covering
// every Vista+ x64 build. The single-signature suffices because the
// terminal-services bootstrap function prologue is unusually stable.
var tspkgSignatureCommon = []byte{
	0x48, 0x83, 0xEC, 0x20,
	0x48, 0x8B, 0x0D,
}

// tspkgLayoutCommon — KIWI_TS_CREDENTIAL outer-node layout per
// KvcForensic JSON: luid_offset=16, primary_offset=24. Inner
// KIWI_TS_PRIMARY_CREDENTIAL UNICODE_STRING offsets (UserName=0x00,
// Domain=0x10, Password=0x20) are stable across builds and live in
// tspkg.go's decodeTSPkgNode.
var tspkgLayoutCommon = TSPkgLayout{
	NodeSize:         0x20,
	LUIDOffset:       0x10,
	PrimaryPtrOffset: 0x18,
}

// ===== Kerberos signature + layout (per KvcForensic) ================

// kerberosSignatureCommon — KvcForensic `Kerberos_x64_vista_plus`.
// One 6-byte signature covers Vista → Win 11 25H2 / Server 2025 (the
// kerberos.dll bootstrap function prologue is unusually stable).
//
//	48 8B 18           mov    rbx, [rax]
//	48 8D 0D           lea    rcx, [rip+rel32]   ← session list head
var kerberosSignatureCommon = []byte{
	0x48, 0x8B, 0x18,
	0x48, 0x8D, 0x0D,
}

// kerberosLayoutCommon — every offset transcribed from KvcForensic
// `Kerberos_x64_vista_plus`. Stable Vista → 25H2.
var kerberosLayoutCommon = KerberosLayout{
	NodeSize:                0x180, // largest field at 0x148+8 = 0x150
	LUIDOffset:              0x40,  // session_luid_offset = 64
	UserNameOffset:          0x78,  // session_username_offset = 120
	DomainOffset:            0x88,  // session_domain_offset = 136
	PasswordOffset:          0xA8,  // session_password_ustr_offset = 168
	LUIDFallbackOffsets:     []uint32{56, 48, 72, 40, 32},
	TicketListOffsets:       []uint32{280, 304, 328}, // 0x118, 0x130, 0x148
	TicketServiceNameOffset: 0x20,                    // 32
	TicketTargetNameOffset:  0x28,                    // 40
	TicketClientNameOffset:  0x90,                    // 144
	TicketFlagsOffset:       0xA0,                    // 160
	TicketKeyTypeOffset:     0xB4,                    // 180
	TicketEncTypeOffset:     0x134,                   // 308
	TicketKvnoOffset:        0x138,                   // 312
	TicketBufferLenOffset:   0x140,                   // 320
	TicketBufferPtrOffset:   0x148,                   // 328
	TicketNodeSize:          0x180,                   // covers up to ptr+8
}

// ===== builtinTemplates ==============================================
//
// Every Template documents its target builds, OS family, validation
// markers (★/◎/▲), and which KvcForensic JSON range it corresponds
// to. The registry stays sorted by BuildMin ascending; KvcForensic's
// boundaries are reproduced exactly.

var builtinTemplates = []*Template{
	{
		// ▲ Win 7 RTM / SP1 / Server 2008 R2 (builds 7600-9199).
		// KvcForensic `MSV_x64_61`. LSA crypto values from pypykatz
		// `LSADecryptorTemplate_x64_NT6_1_7601`.
		BuildMin:                  7600,
		BuildMax:                  9199,
		IVPattern:                 lsaSignatureWin7Sp1,
		IVWildcards:               lsaWildcardsWin7Sp1,
		IVOffset:                  -0x16,
		Key3DESPattern:            lsaSignatureWin7Sp1,
		Key3DESWildcards:          lsaWildcardsWin7Sp1,
		Key3DESOffset:             -0x44,
		KeyAESPattern:             lsaSignatureWin7Sp1,
		KeyAESWildcards:           lsaWildcardsWin7Sp1,
		KeyAESOffset:              -0x68,
		LogonSessionListPattern:   msvSignatureWin7,
		LogonSessionListOffset:    19, // KvcForensic first_entry_offset
		LogonSessionListCount:     1,
		MSVLayout:                 msvLayoutKiwiList52,
		WdigestListPattern:        wdigestSignaturePre11,
		WdigestListOffset:         -4,
		WdigestLayout:             wdigestLayoutCommon,
		TSPkgListPattern:          tspkgSignatureCommon,
		TSPkgListOffset:           7, // KvcForensic first_entry_offset
		TSPkgLayout:               tspkgLayoutCommon,
		KerberosListPattern:       kerberosSignatureCommon,
		KerberosListOffset:        6, // KvcForensic first_entry_offset
		KerberosLayout:            kerberosLayoutCommon,
	},
	{
		// ▲ Win 8 / Server 2012 (builds 9200-9599).
		// KvcForensic `MSV_x64_62`. LSA crypto from pypykatz
		// `LSADecryptorTemplate_x64_NT6_2_9200`.
		BuildMin:                9200,
		BuildMax:                9599,
		IVPattern:               lsaSignatureWin8,
		IVOffset:                -0x4C,
		Key3DESPattern:          lsaSignatureWin8,
		Key3DESOffset:           -0x76,
		KeyAESPattern:           lsaSignatureWin8,
		KeyAESOffset:            -0x07,
		LogonSessionListPattern: msvSignatureWin8,
		LogonSessionListOffset:  16, // KvcForensic first_entry_offset
		LogonSessionListCount:   2,
		MSVLayout:               msvLayoutKiwiList60,
		WdigestListPattern:      wdigestSignaturePre11,
		WdigestListOffset:       -4,
		WdigestLayout:           wdigestLayoutCommon,
		TSPkgListPattern:        tspkgSignatureCommon,
		TSPkgListOffset:         7,
		TSPkgLayout:             tspkgLayoutCommon,
		KerberosListPattern:     kerberosSignatureCommon,
		KerberosListOffset:      6,
		KerberosLayout:          kerberosLayoutCommon,
	},
	{
		// ◎ Win 8.1 / Server 2012 R2 (builds 9600-10239).
		// KvcForensic `MSV_x64_63` ships a distinct signature for
		// this range — different bytes from Win 10 forward despite
		// the LSA signature being shared.
		BuildMin:                9600,
		BuildMax:                10239,
		IVPattern:               lsaSignatureCommon,
		IVOffset:                0x43,
		Key3DESPattern:          lsaSignatureCommon,
		Key3DESOffset:           -0x59,
		KeyAESPattern:           lsaSignatureCommon,
		KeyAESOffset:            0x10,
		LogonSessionListPattern: msvSignatureWin81,
		LogonSessionListOffset:  36, // KvcForensic first_entry_offset
		LogonSessionListCount:   32,
		MSVLayout:               msvLayoutKiwiList61,
		WdigestListPattern:      wdigestSignaturePre11,
		WdigestListOffset:       -4,
		WdigestLayout:           wdigestLayoutCommon,
		TSPkgListPattern:        tspkgSignatureCommon,
		TSPkgListOffset:         7,
		TSPkgLayout:             tspkgLayoutCommon,
		KerberosListPattern:     kerberosSignatureCommon,
		KerberosListOffset:      6,
		KerberosLayout:          kerberosLayoutCommon,
	},
	{
		// ◎ Win 10 1507 / 1511 / 1607 / Server 2016 (builds
		// 10240-15062). KvcForensic `MSV_x64_10_1507_1607`. DPAPI
		// available from build 14393.
		BuildMin:                10240,
		BuildMax:                15062,
		IVPattern:               lsaSignatureCommon,
		IVOffset:                0x43,
		Key3DESPattern:          lsaSignatureCommon,
		Key3DESOffset:           -0x59,
		KeyAESPattern:           lsaSignatureCommon,
		KeyAESOffset:            0x10,
		LogonSessionListPattern: msvSignatureWin8, // same bytes as _62
		LogonSessionListOffset:  16,                // KvcForensic first_entry_offset
		LogonSessionListCount:   32,
		MSVLayout:               msvLayoutKiwiList61,
		WdigestListPattern:      wdigestSignaturePre11,
		WdigestListOffset:       -4,
		WdigestLayout:           wdigestLayoutCommon,
		DPAPIListPattern:        dpapiSignatureWin10Plus,
		DPAPIListOffset:         11, // KvcForensic first_entry_offset
		DPAPILayout:             dpapiLayoutCommon,
		TSPkgListPattern:        tspkgSignatureCommon,
		TSPkgListOffset:         7,
		TSPkgLayout:             tspkgLayoutCommon,
		KerberosListPattern:     kerberosSignatureCommon,
		KerberosListOffset:      6,
		KerberosLayout:          kerberosLayoutCommon,
	},
	{
		// ◎ Win 10 1703 / 1709 (builds 15063-17133). KvcForensic
		// `MSV_x64_1703` — distinct signature from neighbouring
		// ranges.
		BuildMin:                15063,
		BuildMax:                17133,
		IVPattern:               lsaSignatureCommon,
		IVOffset:                0x43,
		Key3DESPattern:          lsaSignatureCommon,
		Key3DESOffset:           -0x59,
		KeyAESPattern:           lsaSignatureCommon,
		KeyAESOffset:            0x10,
		LogonSessionListPattern: msvSignatureWin10Cu,
		LogonSessionListOffset:  23, // KvcForensic first_entry_offset
		LogonSessionListCount:   32,
		MSVLayout:               msvLayoutKiwiList62,
		WdigestListPattern:      wdigestSignaturePre11,
		WdigestListOffset:       -4,
		WdigestLayout:           wdigestLayoutCommon,
		DPAPIListPattern:        dpapiSignatureWin10Plus,
		DPAPIListOffset:         11,
		DPAPILayout:             dpapiLayoutCommon,
		TSPkgListPattern:        tspkgSignatureCommon,
		TSPkgListOffset:         7, // KvcForensic first_entry_offset
		TSPkgLayout:             tspkgLayoutCommon,
		KerberosListPattern:     kerberosSignatureCommon,
		KerberosListOffset:      6, // KvcForensic first_entry_offset
		KerberosLayout:          kerberosLayoutCommon,
	},
	{
		// ◎ Win 10 1803 → 22H2 / Server 2019 (builds 17134-20347).
		// KvcForensic `MSV_x64_1803_22H2`. The LIST_63 layout shipped
		// in v0.23.x covers this range.
		BuildMin:                17134,
		BuildMax:                20347,
		IVPattern:               lsaSignatureCommon,
		IVOffset:                0x43,
		Key3DESPattern:          lsaSignatureCommon,
		Key3DESOffset:           -0x59,
		KeyAESPattern:           lsaSignatureCommon,
		KeyAESOffset:            0x10,
		LogonSessionListPattern: msvSignatureWin8, // same bytes as _62
		LogonSessionListOffset:  23,                // KvcForensic first_entry_offset
		LogonSessionListCount:   32,
		MSVLayout:               msvLayoutKiwiList63,
		WdigestListPattern:      wdigestSignaturePre11,
		WdigestListOffset:       -4,
		WdigestLayout:           wdigestLayoutCommon,
		DPAPIListPattern:        dpapiSignatureWin10Plus,
		DPAPIListOffset:         11,
		DPAPILayout:             dpapiLayoutCommon,
		TSPkgListPattern:        tspkgSignatureCommon,
		TSPkgListOffset:         7, // KvcForensic first_entry_offset
		TSPkgLayout:             tspkgLayoutCommon,
		KerberosListPattern:     kerberosSignatureCommon,
		KerberosListOffset:      6, // KvcForensic first_entry_offset
		KerberosLayout:          kerberosLayoutCommon,
	},
	{
		// ◎ Server 2022 + Win 11 21H2 (builds 20348-22099).
		// KvcForensic `MSV_x64_11_2022`. NT 10.0 family, but the MSV
		// signature swaps to the `45 89 34 24` prefix.
		BuildMin:                20348,
		BuildMax:                22099,
		IVPattern:               lsaSignatureCommon,
		IVOffset:                0x43,
		Key3DESPattern:          lsaSignatureCommon,
		Key3DESOffset:           -0x59,
		KeyAESPattern:           lsaSignatureCommon,
		KeyAESOffset:            0x10,
		LogonSessionListPattern: msvSignatureWin11Rtm,
		LogonSessionListOffset:  24, // KvcForensic first_entry_offset
		LogonSessionListCount:   32,
		MSVLayout:               msvLayoutKiwiList64,
		WdigestListPattern:      wdigestSignaturePre11, // pre-22000 still
		WdigestListOffset:       -4,
		WdigestLayout:           wdigestLayoutCommon,
		DPAPIListPattern:        dpapiSignatureWin10Plus,
		DPAPIListOffset:         11,
		DPAPILayout:             dpapiLayoutCommon,
		TSPkgListPattern:        tspkgSignatureCommon,
		TSPkgListOffset:         7, // KvcForensic first_entry_offset
		TSPkgLayout:             tspkgLayoutCommon,
		KerberosListPattern:     kerberosSignatureCommon,
		KerberosListOffset:      6, // KvcForensic first_entry_offset
		KerberosLayout:          kerberosLayoutCommon,
	},
	{
		// ◎ Win 11 22H2 / 23H2 (builds 22100-26099). KvcForensic
		// `MSV_x64_11_2023` + Wdigest `WDigest_x64_11plus`.
		BuildMin:                22100,
		BuildMax:                26099,
		IVPattern:               lsaSignatureCommon,
		IVOffset:                0x43,
		Key3DESPattern:          lsaSignatureCommon,
		Key3DESOffset:           -0x59,
		KeyAESPattern:           lsaSignatureCommon,
		KeyAESOffset:            0x10,
		LogonSessionListPattern: msvSignatureWin1122H2,
		LogonSessionListOffset:  27, // KvcForensic first_entry_offset
		LogonSessionListCount:   32,
		MSVLayout:               msvLayoutKiwiList64,
		WdigestListPattern:      wdigestSignatureWin11Plus,
		WdigestListOffset:       -4,
		WdigestLayout:           wdigestLayoutCommon,
		DPAPIListPattern:        dpapiSignatureWin10Plus,
		DPAPIListOffset:         11,
		DPAPILayout:             dpapiLayoutCommon,
		TSPkgListPattern:        tspkgSignatureCommon,
		TSPkgListOffset:         7, // KvcForensic first_entry_offset
		TSPkgLayout:             tspkgLayoutCommon,
		KerberosListPattern:     kerberosSignatureCommon,
		KerberosListOffset:      6, // KvcForensic first_entry_offset
		KerberosLayout:          kerberosLayoutCommon,
	},
	{
		// ◎ Win 11 24H2 / 25H2 / Server 2025 (builds 26100+).
		// KvcForensic `MSV_x64_11_24H2` + parser_support: true layout.
		// LSA IV offset shifts from 0x43 to 0x47 per KvcForensic
		// `LSA_24H2_plus`.
		BuildMin:                26100,
		BuildMax:                4294967295, // KvcForensic uses uint32 max
		IVPattern:               lsaSignatureCommon,
		IVOffset:                0x47, // KvcForensic offset_to_iv_ptr = 71
		Key3DESPattern:          lsaSignatureCommon,
		Key3DESOffset:           -0x59,
		KeyAESPattern:           lsaSignatureCommon,
		KeyAESOffset:            0x10,
		LogonSessionListPattern: msvSignatureWin1124H2,
		LogonSessionListOffset:  25, // KvcForensic first_entry_offset
		LogonSessionListCount:   32,
		MSVLayout:               msvLayoutKiwiList65,
		WdigestListPattern:      wdigestSignatureWin11Plus,
		WdigestListOffset:       -4,
		WdigestLayout:           wdigestLayoutCommon,
		DPAPIListPattern:        dpapiSignatureWin10Plus,
		DPAPIListOffset:         11,
		DPAPILayout:             dpapiLayoutCommon,
		TSPkgListPattern:        tspkgSignatureCommon,
		TSPkgListOffset:         7, // KvcForensic first_entry_offset
		TSPkgLayout:             tspkgLayoutCommon,
		KerberosListPattern:     kerberosSignatureCommon,
		KerberosListOffset:      6, // KvcForensic first_entry_offset
		KerberosLayout:          kerberosLayoutCommon,
	},
}
