package sekurlsa

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"

	"github.com/oioio-space/maldev/internal/krb5/iana/asnAppTag"
	"github.com/oioio-space/maldev/internal/krb5/iana/msgtype"
	"github.com/oioio-space/maldev/internal/krb5/messages"
	"github.com/oioio-space/maldev/internal/krb5/types"
)

// fixtureTicket builds a minimal but valid messages.Ticket with the
// APPLICATION 1 tag wrapping a SEQUENCE of {tkt-vno, realm, sname,
// enc-part}. The enc-part cipher is a fixed 32-byte blob — large
// enough for downstream parsers to accept, small enough to keep the
// fixture compact.
func fixtureTicketBytes(t *testing.T) []byte {
	t.Helper()
	ticket := messages.Ticket{
		TktVNO: 5,
		Realm:  "CORP.LOCAL",
		SName: types.PrincipalName{
			NameType:   2, // KRB_NT_SRV_INST
			NameString: []string{"krbtgt", "CORP.LOCAL"},
		},
		EncPart: types.EncryptedData{
			EType:  18, // AES256
			KVNO:   2,
			Cipher: make([]byte, 32),
		},
	}
	b, err := ticket.Marshal()
	if err != nil {
		t.Fatalf("fixture Ticket.Marshal: %v", err)
	}
	return b
}

func TestKerberosTicket_ToKirbi_RoundTrip(t *testing.T) {
	tkt := KerberosTicket{
		ServiceName: "krbtgt",
		TargetName:  "CORP.LOCAL",
		ClientName:  "alice@CORP.LOCAL",
		Flags:       0x40e10000, // forwardable + renewable + initial — typical TGT flags
		KeyType:     18,
		EncType:     18,
		KVNO:        2,
		Buffer:      fixtureTicketBytes(t),
	}

	out, err := tkt.ToKirbi()
	if err != nil {
		t.Fatalf("ToKirbi: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("ToKirbi returned empty bytes")
	}

	// Round-trip: the produced bytes must parse back as KRB_CRED.
	var cred messages.KRBCred
	if err := cred.Unmarshal(out); err != nil {
		t.Fatalf("output is not a valid KRB_CRED: %v\nfirst 32 bytes: % x", err, out[:min(32, len(out))])
	}
	if cred.MsgType != msgtype.KRB_CRED {
		t.Errorf("MsgType = %d, want %d (KRB_CRED)", cred.MsgType, msgtype.KRB_CRED)
	}
	if cred.PVNO != pvnoKerberosV5 {
		t.Errorf("PVNO = %d, want %d", cred.PVNO, pvnoKerberosV5)
	}
	if got := len(cred.Tickets); got != 1 {
		t.Fatalf("Tickets count = %d, want 1", got)
	}
	if cred.Tickets[0].Realm != "CORP.LOCAL" {
		t.Errorf("Tickets[0].Realm = %q, want %q", cred.Tickets[0].Realm, "CORP.LOCAL")
	}
	if cred.EncPart.EType != 0 {
		t.Errorf("EncPart.EType = %d, want 0 (unencrypted convention)", cred.EncPart.EType)
	}
}

func TestKerberosTicket_ToKirbi_EncKrbCredPart_HasMetadata(t *testing.T) {
	tkt := KerberosTicket{
		ServiceName: "cifs",
		TargetName:  "FILESERVER.CORP.LOCAL",
		ClientName:  "alice@CORP.LOCAL",
		Flags:       0x40a10000,
		KeyType:     17, // AES128
		Buffer:      fixtureTicketBytes(t),
	}

	out, err := tkt.ToKirbi()
	if err != nil {
		t.Fatalf("ToKirbi: %v", err)
	}

	var cred messages.KRBCred
	if err := cred.Unmarshal(out); err != nil {
		t.Fatalf("Unmarshal KRBCred: %v", err)
	}
	if cred.EncPart.EType != 0 {
		t.Fatalf("EncPart not unencrypted (EType=%d) — can't decode plaintext", cred.EncPart.EType)
	}

	// EncPart.Cipher is plaintext DER of EncKrbCredPart (etype 0
	// convention). Strip the APPLICATION 29 wrapper that
	// EncKrbCredPart.Marshal added, then unmarshal.
	var enc messages.EncKrbCredPart
	if err := enc.Unmarshal(cred.EncPart.Cipher); err != nil {
		t.Fatalf("Unmarshal EncKrbCredPart from cipher: %v", err)
	}
	if got := len(enc.TicketInfo); got != 1 {
		t.Fatalf("TicketInfo count = %d, want 1", got)
	}
	info := enc.TicketInfo[0]
	if info.PRealm != "CORP.LOCAL" {
		t.Errorf("PRealm = %q, want %q", info.PRealm, "CORP.LOCAL")
	}
	if got := strings.Join(info.PName.NameString, "/"); got != "alice" {
		t.Errorf("PName = %q, want %q", got, "alice")
	}
	if info.SRealm != "FILESERVER.CORP.LOCAL" {
		t.Errorf("SRealm = %q, want %q", info.SRealm, "FILESERVER.CORP.LOCAL")
	}
	if got := strings.Join(info.SName.NameString, "/"); got != "cifs" {
		t.Errorf("SName = %q, want %q", got, "cifs")
	}
	if info.Key.KeyType != 17 {
		t.Errorf("Key.KeyType = %d, want 17", info.Key.KeyType)
	}
}

func TestKerberosTicket_ToKirbi_RejectsEmptyBuffer(t *testing.T) {
	tkt := KerberosTicket{ServiceName: "krbtgt"}
	_, err := tkt.ToKirbi()
	if !errors.Is(err, ErrKirbiInvalidTicket) {
		t.Fatalf("err = %v, want wrap of ErrKirbiInvalidTicket", err)
	}
}

func TestKerberosTicket_ToKirbi_RejectsMalformedBuffer(t *testing.T) {
	tkt := KerberosTicket{
		Buffer: []byte{0x00, 0x01, 0x02, 0x03}, // not an APPLICATION 1 SEQUENCE
	}
	_, err := tkt.ToKirbi()
	if !errors.Is(err, ErrKirbiInvalidTicket) {
		t.Fatalf("err = %v, want wrap of ErrKirbiInvalidTicket", err)
	}
}

func TestKerberosTicket_ToKirbi_OuterTagIsApplication22(t *testing.T) {
	tkt := KerberosTicket{
		ServiceName: "krbtgt",
		TargetName:  "CORP.LOCAL",
		ClientName:  "bob",
		Buffer:      fixtureTicketBytes(t),
	}
	out, err := tkt.ToKirbi()
	if err != nil {
		t.Fatalf("ToKirbi: %v", err)
	}
	// First byte is the APPLICATION-tagged identifier:
	//   class=01 (application) + form=1 (constructed) + tag=22 (KRBCred)
	//   = 0b01 100000 + 0b10110 = 0x76
	if out[0] != 0x76 {
		t.Fatalf("outer tag byte = 0x%02X, want 0x76 (APPLICATION 22 constructed); asnAppTag.KRBCred=%d", out[0], asnAppTag.KRBCred)
	}
}

func TestKerberosTicket_ToKirbiFile_WritesValidFile(t *testing.T) {
	dir := t.TempDir()
	tkt := KerberosTicket{
		ServiceName: "krbtgt",
		TargetName:  "CORP.LOCAL",
		ClientName:  "alice@CORP.LOCAL",
		Buffer:      fixtureTicketBytes(t),
	}

	path, err := tkt.ToKirbiFile(dir)
	if err != nil {
		t.Fatalf("ToKirbiFile: %v", err)
	}
	if !strings.HasSuffix(path, ".kirbi") {
		t.Errorf("path = %q, want .kirbi extension", path)
	}
	if !strings.HasPrefix(filepath.Base(path), "") {
		t.Errorf("filename empty: %q", path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read written file: %v", err)
	}
	var cred messages.KRBCred
	if err := cred.Unmarshal(data); err != nil {
		t.Fatalf("written file is not a valid KRB_CRED: %v", err)
	}
	if cred.MsgType != msgtype.KRB_CRED {
		t.Errorf("MsgType = %d, want %d", cred.MsgType, msgtype.KRB_CRED)
	}
}

func TestKerberosTicket_ToKirbi_PopulatesSessionKey(t *testing.T) {
	want := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
		0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00}
	tkt := KerberosTicket{
		ServiceName: "krbtgt",
		ClientName:  "alice@CORP.LOCAL",
		KeyType:     17, // AES128
		Buffer:      fixtureTicketBytes(t),
		SessionKey:  want,
	}

	out, err := tkt.ToKirbi()
	if err != nil {
		t.Fatalf("ToKirbi: %v", err)
	}
	var cred messages.KRBCred
	if err := cred.Unmarshal(out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	var enc messages.EncKrbCredPart
	if err := enc.Unmarshal(cred.EncPart.Cipher); err != nil {
		t.Fatalf("Unmarshal EncKrbCredPart: %v", err)
	}
	got := enc.TicketInfo[0].Key.KeyValue
	if string(got) != string(want) {
		t.Fatalf("Key.KeyValue = % X, want % X", got, want)
	}
	if enc.TicketInfo[0].Key.KeyType != 17 {
		t.Errorf("Key.KeyType = %d, want 17", enc.TicketInfo[0].Key.KeyType)
	}
}

func TestKerberosTicket_ToKirbi_FlagsBitStringIs32Bits(t *testing.T) {
	tkt := KerberosTicket{
		Flags:  0xDEADBEEF,
		Buffer: fixtureTicketBytes(t),
	}
	out, err := tkt.ToKirbi()
	if err != nil {
		t.Fatalf("ToKirbi: %v", err)
	}
	var cred messages.KRBCred
	if err := cred.Unmarshal(out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	var enc messages.EncKrbCredPart
	if err := enc.Unmarshal(cred.EncPart.Cipher); err != nil {
		t.Fatalf("Unmarshal EncKrbCredPart: %v", err)
	}
	flags := enc.TicketInfo[0].Flags
	if flags.BitLength != 32 {
		t.Errorf("BitLength = %d, want 32", flags.BitLength)
	}
	want := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	if string(flags.Bytes) != string(want) {
		t.Errorf("Bytes = % X, want % X", flags.Bytes, want)
	}
}

func TestSplitClientName(t *testing.T) {
	cases := []struct {
		in        string
		wantPName []string
		wantRealm string
	}{
		{"alice@CORP.LOCAL", []string{"alice"}, "CORP.LOCAL"},
		{`CORP\bob`, []string{"bob"}, "CORP"},
		{"carol", []string{"carol"}, ""},
		{"", []string{""}, ""},
	}
	for _, c := range cases {
		gotName, gotRealm := splitClientName(c.in)
		if strings.Join(gotName, "/") != strings.Join(c.wantPName, "/") || gotRealm != c.wantRealm {
			t.Errorf("splitClientName(%q) = %v, %q; want %v, %q",
				c.in, gotName, gotRealm, c.wantPName, c.wantRealm)
		}
	}
}

func TestFlagsToBitString_LayoutMatches32BitBigEndian(t *testing.T) {
	bs := flagsToBitString(0x12345678)
	if bs.BitLength != 32 {
		t.Errorf("BitLength = %d, want 32", bs.BitLength)
	}
	want := []byte{0x12, 0x34, 0x56, 0x78}
	if string(bs.Bytes) != string(want) {
		t.Errorf("Bytes = % X, want % X", bs.Bytes, want)
	}
	// Ensure asn1 round-trip preserves the 32-bit layout.
	der, err := asn1.Marshal(bs)
	if err != nil {
		t.Fatalf("asn1.Marshal: %v", err)
	}
	var rt asn1.BitString
	if _, err := asn1.Unmarshal(der, &rt); err != nil {
		t.Fatalf("asn1.Unmarshal: %v", err)
	}
	if rt.BitLength != 32 || string(rt.Bytes) != string(want) {
		t.Errorf("round-trip drift: BitLength=%d Bytes=% X", rt.BitLength, rt.Bytes)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
