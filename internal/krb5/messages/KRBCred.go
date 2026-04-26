package messages

import (
	"fmt"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/oioio-space/maldev/internal/krb5/asn1tools"
	"github.com/oioio-space/maldev/internal/krb5/crypto"
	"github.com/oioio-space/maldev/internal/krb5/iana/asnAppTag"
	"github.com/oioio-space/maldev/internal/krb5/iana/keyusage"
	"github.com/oioio-space/maldev/internal/krb5/iana/msgtype"
	"github.com/oioio-space/maldev/internal/krb5/krberror"
	"github.com/oioio-space/maldev/internal/krb5/types"
)

type marshalKRBCred struct {
	PVNO    int                 `asn1:"explicit,tag:0"`
	MsgType int                 `asn1:"explicit,tag:1"`
	Tickets asn1.RawValue       `asn1:"explicit,tag:2"`
	EncPart types.EncryptedData `asn1:"explicit,tag:3"`
}

// KRBCred implements RFC 4120 KRB_CRED: https://tools.ietf.org/html/rfc4120#section-5.8.1.
type KRBCred struct {
	PVNO             int
	MsgType          int
	Tickets          []Ticket
	EncPart          types.EncryptedData
	DecryptedEncPart EncKrbCredPart
}

// EncKrbCredPart is the encrypted part of KRB_CRED.
type EncKrbCredPart struct {
	TicketInfo []KrbCredInfo     `asn1:"explicit,tag:0"`
	Nouce      int               `asn1:"optional,explicit,tag:1"`
	Timestamp  time.Time         `asn1:"generalized,optional,explicit,tag:2"`
	Usec       int               `asn1:"optional,explicit,tag:3"`
	SAddress   types.HostAddress `asn1:"optional,explicit,tag:4"`
	RAddress   types.HostAddress `asn1:"optional,explicit,tag:5"`
}

// KrbCredInfo is the KRB_CRED_INFO part of KRB_CRED.
type KrbCredInfo struct {
	Key       types.EncryptionKey `asn1:"explicit,tag:0"`
	PRealm    string              `asn1:"generalstring,optional,explicit,tag:1"`
	PName     types.PrincipalName `asn1:"optional,explicit,tag:2"`
	Flags     asn1.BitString      `asn1:"optional,explicit,tag:3"`
	AuthTime  time.Time           `asn1:"generalized,optional,explicit,tag:4"`
	StartTime time.Time           `asn1:"generalized,optional,explicit,tag:5"`
	EndTime   time.Time           `asn1:"generalized,optional,explicit,tag:6"`
	RenewTill time.Time           `asn1:"generalized,optional,explicit,tag:7"`
	SRealm    string              `asn1:"optional,explicit,ia5,tag:8"`
	SName     types.PrincipalName `asn1:"optional,explicit,tag:9"`
	CAddr     types.HostAddresses `asn1:"optional,explicit,tag:10"`
}

// Unmarshal bytes b into the KRBCred struct.
func (k *KRBCred) Unmarshal(b []byte) error {
	var m marshalKRBCred
	_, err := asn1.UnmarshalWithParams(b, &m, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.KRBCred))
	if err != nil {
		return processUnmarshalReplyError(b, err)
	}
	expectedMsgType := msgtype.KRB_CRED
	if m.MsgType != expectedMsgType {
		return krberror.NewErrorf(krberror.KRBMsgError, "message ID does not indicate a KRB_CRED. Expected: %v; Actual: %v", expectedMsgType, m.MsgType)
	}
	k.PVNO = m.PVNO
	k.MsgType = m.MsgType
	k.EncPart = m.EncPart
	if len(m.Tickets.Bytes) > 0 {
		k.Tickets, err = unmarshalTicketsSequence(m.Tickets)
		if err != nil {
			return krberror.Errorf(err, krberror.EncodingError, "error unmarshaling tickets within KRB_CRED")
		}
	}
	return nil
}

// DecryptEncPart decrypts the encrypted part of a KRB_CRED.
func (k *KRBCred) DecryptEncPart(key types.EncryptionKey) error {
	b, err := crypto.DecryptEncPart(k.EncPart, key, keyusage.KRB_CRED_ENCPART)
	if err != nil {
		return krberror.Errorf(err, krberror.DecryptingError, "error decrypting KRB_CRED EncPart")
	}
	var denc EncKrbCredPart
	err = denc.Unmarshal(b)
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "error unmarshaling encrypted part of KRB_CRED")
	}
	k.DecryptedEncPart = denc
	return nil
}

// Unmarshal bytes b into the encrypted part of KRB_CRED.
func (k *EncKrbCredPart) Unmarshal(b []byte) error {
	_, err := asn1.UnmarshalWithParams(b, k, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.EncKrbCredPart))
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "error unmarshaling EncKrbCredPart")
	}
	return nil
}

// Marshal returns the DER encoding of the KRB_CRED with the
// APPLICATION 22 outer tag, ready to be written to a .kirbi file or
// transmitted in a KRB-CRED protocol message. Tickets is required;
// EncPart should be set to either an encrypted EncKrbCredPart cipher
// or — for unencrypted "operator-friendly" .kirbi (the common
// mimikatz convention) — a zero-etype EncryptedData wrapping the DER
// of the EncKrbCredPart in plaintext.
func (k *KRBCred) Marshal() ([]byte, error) {
	tickets, err := marshalTicketsSequence(k.Tickets)
	if err != nil {
		return nil, krberror.Errorf(err, krberror.EncodingError, "marshaling KRB_CRED tickets")
	}
	m := marshalKRBCred{
		PVNO:    k.PVNO,
		MsgType: k.MsgType,
		Tickets: tickets,
		EncPart: k.EncPart,
	}
	b, err := asn1.Marshal(m)
	if err != nil {
		return nil, krberror.Errorf(err, krberror.EncodingError, "marshaling KRB_CRED outer SEQUENCE")
	}
	return asn1tools.AddASNAppTag(b, asnAppTag.KRBCred), nil
}

// Marshal returns the DER encoding of the EncKrbCredPart with the
// APPLICATION 29 outer tag. Used to build the cipher field of a
// KRB_CRED.EncPart — when the operator wants an unencrypted .kirbi
// (etype=0), feed this output directly as EncryptedData.Cipher.
func (k *EncKrbCredPart) Marshal() ([]byte, error) {
	b, err := asn1.Marshal(*k)
	if err != nil {
		return nil, krberror.Errorf(err, krberror.EncodingError, "marshaling EncKrbCredPart")
	}
	return asn1tools.AddASNAppTag(b, asnAppTag.EncKrbCredPart), nil
}

// marshalTicketsSequence encodes []Ticket as the [2] EXPLICIT
// SEQUENCE OF Ticket expected by KRB_CRED's tickets field. Each
// Ticket carries its own APPLICATION 1 tag (added by Ticket.Marshal).
//
// We have to materialize the [2] EXPLICIT wrapper ourselves and
// stuff the bytes into RawValue.FullBytes — the standard asn1
// encoder doesn't round-trip "explicit context-specific tag around a
// SEQUENCE OF something carrying its own application tags" cleanly
// for RawValue fields. (The same encoding gap that the Unmarshal
// side works around with unmarshalTicketsSequence.)
//
// Layout produced:
//
//	A2 LLouter            -- [2] EXPLICIT context-specific
//	  30 LLinner          -- SEQUENCE OF
//	    61 LL [Ticket1]   -- APPLICATION 1 (Ticket)
//	    61 LL [Ticket2]
//	    ...
func marshalTicketsSequence(tickets []Ticket) (asn1.RawValue, error) {
	var concat []byte
	for i := range tickets {
		b, err := tickets[i].Marshal()
		if err != nil {
			return asn1.RawValue{}, fmt.Errorf("ticket %d: %w", i, err)
		}
		concat = append(concat, b...)
	}
	// SEQUENCE OF: 0x30 (universal SEQUENCE, constructed) + length.
	seqOf := append([]byte{byte(0x20 | asn1.TagSequence)},
		append(asn1tools.MarshalLengthBytes(len(concat)), concat...)...)
	// [2] EXPLICIT wrapper: 0xA2 (context-specific class=2,
	// constructed bit set, tag=2) + length + seqOf.
	full := append([]byte{0xA2},
		append(asn1tools.MarshalLengthBytes(len(seqOf)), seqOf...)...)
	return asn1.RawValue{FullBytes: full}, nil
}
