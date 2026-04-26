package goldenticket

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/oioio-space/maldev/internal/krb5/messages"
)

// fixedHash returns a deterministic 16-byte RC4-style key for tests.
// Matches the etype.keyLen() so it satisfies normalize().
func fixedHash() Hash {
	return Hash{
		Type:  ETypeRC4HMAC,
		Bytes: bytes.Repeat([]byte{0xAB}, 16),
	}
}

func okParams() Params {
	return Params{
		Domain:    "corp.example.com",
		DomainSID: "S-1-5-21-1004336348-1177238915-682003330",
		Hash:      fixedHash(),
		Now:       time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
	}
}

func TestForge_RejectsMissingDomain(t *testing.T) {
	p := okParams()
	p.Domain = ""
	_, err := Forge(p)
	if !errors.Is(err, ErrInvalidParams) {
		t.Fatalf("err = %v, want wrap of ErrInvalidParams", err)
	}
	if !strings.Contains(err.Error(), "Domain is required") {
		t.Errorf("err message %q does not mention Domain", err.Error())
	}
}

func TestForge_RejectsMissingDomainSID(t *testing.T) {
	p := okParams()
	p.DomainSID = ""
	_, err := Forge(p)
	if !errors.Is(err, ErrInvalidParams) {
		t.Fatalf("err = %v, want wrap of ErrInvalidParams", err)
	}
}

func TestForge_RejectsMalformedDomainSID(t *testing.T) {
	p := okParams()
	p.DomainSID = "not-a-sid"
	_, err := Forge(p)
	if !errors.Is(err, ErrInvalidParams) {
		t.Fatalf("err = %v, want wrap of ErrInvalidParams", err)
	}
	if !strings.Contains(err.Error(), "S-1-5-21-") {
		t.Errorf("err message %q does not surface the expected prefix hint", err.Error())
	}
}

func TestForge_RejectsEmptyHashBytes(t *testing.T) {
	p := okParams()
	p.Hash = Hash{Type: ETypeRC4HMAC, Bytes: nil}
	_, err := Forge(p)
	if !errors.Is(err, ErrInvalidParams) {
		t.Fatalf("err = %v, want wrap of ErrInvalidParams", err)
	}
}

func TestForge_RejectsHashLengthMismatch(t *testing.T) {
	p := okParams()
	p.Hash = Hash{Type: ETypeAES256CTS, Bytes: bytes.Repeat([]byte{0xCC}, 16)} // wrong size
	_, err := Forge(p)
	if !errors.Is(err, ErrInvalidParams) {
		t.Fatalf("err = %v, want wrap of ErrInvalidParams", err)
	}
}

func TestForge_RejectsUnsupportedEType(t *testing.T) {
	p := okParams()
	p.Hash = Hash{Type: EType(99), Bytes: bytes.Repeat([]byte{0xDD}, 16)}
	_, err := Forge(p)
	if !errors.Is(err, ErrInvalidParams) {
		t.Fatalf("err = %v, want wrap of ErrInvalidParams", err)
	}
}

func TestForge_HappyPathRC4_ProducesParseableKirbi(t *testing.T) {
	kirbi, err := Forge(okParams())
	if err != nil {
		t.Fatalf("Forge: %v", err)
	}
	if len(kirbi) < 200 {
		t.Errorf("kirbi seems too small: %d bytes", len(kirbi))
	}
	// The kirbi must be a parseable KRB-CRED.
	var c messages.KRBCred
	if err := c.Unmarshal(kirbi); err != nil {
		t.Fatalf("kirbi does not parse as KRB-CRED: %v", err)
	}
	if got := len(c.Tickets); got != 1 {
		t.Fatalf("ticket count = %d, want 1", got)
	}
	tkt := c.Tickets[0]
	if tkt.Realm != "CORP.EXAMPLE.COM" {
		t.Errorf("ticket Realm = %q, want CORP.EXAMPLE.COM", tkt.Realm)
	}
	if got := tkt.SName.NameString; len(got) != 2 || got[0] != "krbtgt" || got[1] != "CORP.EXAMPLE.COM" {
		t.Errorf("ticket SName = %v, want [krbtgt CORP.EXAMPLE.COM]", got)
	}
	if c.MsgType != 22 {
		t.Errorf("KRB_CRED MsgType = %d, want 22", c.MsgType)
	}
}

func TestForge_DefaultsAppliedFromMinimalParams(t *testing.T) {
	// Minimum-viable Params: Domain + DomainSID + Hash. Forge fills
	// the rest from defaults.
	p := Params{
		Domain:    "corp.example.com",
		DomainSID: "S-1-5-21-1-2-3",
		Hash:      fixedHash(),
		Now:       time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC),
	}
	kirbi, err := Forge(p)
	if err != nil {
		t.Fatalf("Forge minimal: %v", err)
	}
	var c messages.KRBCred
	if err := c.Unmarshal(kirbi); err != nil {
		t.Fatalf("parse kirbi: %v", err)
	}
	// Ticket SName must default to krbtgt/<DOMAIN>.
	got := c.Tickets[0].SName
	if got.NameString[0] != "krbtgt" {
		t.Errorf("default SName[0] = %q, want krbtgt", got.NameString[0])
	}
}

func TestForge_HappyPathAES256_ProducesParseableKirbi(t *testing.T) {
	p := okParams()
	p.Hash = Hash{
		Type:  ETypeAES256CTS,
		Bytes: bytes.Repeat([]byte{0x42}, 32),
	}
	kirbi, err := Forge(p)
	if err != nil {
		t.Fatalf("Forge AES256: %v", err)
	}
	var c messages.KRBCred
	if err := c.Unmarshal(kirbi); err != nil {
		t.Fatalf("AES256 kirbi parse: %v", err)
	}
	if got, want := c.Tickets[0].EncPart.EType, int32(18); got != want {
		t.Errorf("EncPart.EType = %d, want %d (AES256-CTS-HMAC-SHA1-96)", got, want)
	}
}

func TestForge_HappyPathAES128_ProducesParseableKirbi(t *testing.T) {
	p := okParams()
	p.Hash = Hash{
		Type:  ETypeAES128CTS,
		Bytes: bytes.Repeat([]byte{0x37}, 16),
	}
	kirbi, err := Forge(p)
	if err != nil {
		t.Fatalf("Forge AES128: %v", err)
	}
	var c messages.KRBCred
	if err := c.Unmarshal(kirbi); err != nil {
		t.Fatalf("AES128 kirbi parse: %v", err)
	}
	if got, want := c.Tickets[0].EncPart.EType, int32(17); got != want {
		t.Errorf("EncPart.EType = %d, want %d (AES128-CTS-HMAC-SHA1-96)", got, want)
	}
}

func TestForge_DeterministicForFixedParams(t *testing.T) {
	// With Now pinned, the *ticket* part will still vary because the
	// session key is generated randomly. Verify the structure is
	// stable: same Params → same ticket Realm / SName / etype /
	// CName.
	p := okParams()
	a, err := Forge(p)
	if err != nil {
		t.Fatalf("Forge a: %v", err)
	}
	b, err := Forge(p)
	if err != nil {
		t.Fatalf("Forge b: %v", err)
	}
	var ca, cb messages.KRBCred
	if err := ca.Unmarshal(a); err != nil {
		t.Fatalf("parse a: %v", err)
	}
	if err := cb.Unmarshal(b); err != nil {
		t.Fatalf("parse b: %v", err)
	}
	if ca.Tickets[0].Realm != cb.Tickets[0].Realm {
		t.Errorf("Realm differs across forges: %q vs %q", ca.Tickets[0].Realm, cb.Tickets[0].Realm)
	}
	if ca.Tickets[0].EncPart.EType != cb.Tickets[0].EncPart.EType {
		t.Errorf("EncPart.EType differs across forges: %d vs %d", ca.Tickets[0].EncPart.EType, cb.Tickets[0].EncPart.EType)
	}
}
