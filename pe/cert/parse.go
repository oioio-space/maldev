package cert

import (
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/secDre4mer/pkcs7"
)

// ParsedAuthenticode is the structured view of a WIN_CERTIFICATE
// blob (the [Certificate.Raw] payload). Surfaces the signer chain,
// validity window, and the embedded SpcIndirectDataContent the
// signature was computed over — enough to clone the chain into a
// new forge ([Forge]) or compare against a captured PE's
// Authenticode hash to detect post-sign tampering.
//
// Returned by [Certificate.Parse].
type ParsedAuthenticode struct {
	// Header is the WIN_CERTIFICATE preamble (8 bytes: Length /
	// Revision / CertificateType). Surfaced verbatim so callers
	// inspecting unusual cert blobs can route on the type field.
	Header WinCertificateHeader

	// Certs is the full chain carried in the SignedData
	// `certificates` field — leaf first, then any intermediate
	// CAs, root last (when included). PKCS#7 doesn't mandate
	// ordering; callers needing strict leaf/intermediate/root
	// separation should walk by Issuer→Subject relationships.
	Certs []*x509.Certificate

	// Signer is the leaf cert that produced the signature —
	// matches the SignerInfo's IssuerAndSerialNumber against Certs.
	// nil when the SignedData has no signer info.
	Signer *x509.Certificate

	// Issuer is Signer.Issuer.String() in the canonical RFC 4514
	// form. Empty when Signer is nil.
	Issuer string

	// Subject is Signer.Subject.String() in the canonical RFC 4514
	// form. Empty when Signer is nil.
	Subject string

	// Serial is the leaf cert's serial number. nil when Signer
	// is nil.
	Serial *big.Int

	// NotBefore / NotAfter are the leaf cert's validity window.
	// Zero when Signer is nil.
	NotBefore, NotAfter time.Time

	// Algorithm is the leaf cert's signature algorithm
	// (typically SHA256-RSA for modern Authenticode chains).
	Algorithm x509.SignatureAlgorithm
}

// WinCertificateHeader mirrors the Win32 WIN_CERTIFICATE preamble.
type WinCertificateHeader struct {
	// Length is the total bytes including this header. Padding to
	// 8-byte alignment is NOT counted.
	Length uint32
	// Revision: 0x0100 = WIN_CERT_REVISION_1_0,
	//           0x0200 = WIN_CERT_REVISION_2_0 (modern Authenticode).
	Revision uint16
	// CertificateType: 0x0001 = X.509 (legacy), 0x0002 = PKCS_SIGNED_DATA.
	CertificateType uint16
}

// ErrCertificateTooSmall is returned by [Certificate.Parse] when
// the Raw bytes are shorter than the 8-byte WIN_CERTIFICATE header.
var ErrCertificateTooSmall = errors.New("cert: WIN_CERTIFICATE blob is shorter than its 8-byte header")

// ErrCertificateNoSigners is returned by [Certificate.Parse] when
// the parsed PKCS#7 SignedData carries no signer info — the blob
// is structurally a degenerate certs-only message rather than a
// real Authenticode signature.
var ErrCertificateNoSigners = errors.New("cert: PKCS#7 SignedData carries no signer info")

// Inspect is the one-call operator wrapper: read the PE at
// `pePath` via [Read], then [Certificate.Parse] the embedded
// signature blob. Returns [ErrNoCertificate] for unsigned PEs
// (matches [Read]'s contract) and the same parse-side sentinels
// as [Certificate.Parse].
func Inspect(pePath string) (*ParsedAuthenticode, error) {
	c, err := Read(pePath)
	if err != nil {
		return nil, err
	}
	return c.Parse()
}

// Parse decodes the WIN_CERTIFICATE-wrapped PKCS#7 SignedData in
// `c.Raw` into a [ParsedAuthenticode]. Returns
// [ErrCertificateTooSmall] for blobs shorter than the 8-byte header,
// [ErrCertificateNoSigners] when SignedData has no signer info,
// and wrapped pkcs7-parse errors otherwise.
//
// The pure-Go decode (via secDre4mer/pkcs7) needs no Windows API.
func (c *Certificate) Parse() (*ParsedAuthenticode, error) {
	if c == nil || len(c.Raw) < 8 {
		return nil, ErrCertificateTooSmall
	}

	hdr := WinCertificateHeader{
		Length:          binary.LittleEndian.Uint32(c.Raw[0:4]),
		Revision:        binary.LittleEndian.Uint16(c.Raw[4:6]),
		CertificateType: binary.LittleEndian.Uint16(c.Raw[6:8]),
	}
	if int(hdr.Length) < 8 || int(hdr.Length) > len(c.Raw) {
		return nil, fmt.Errorf("cert: WIN_CERTIFICATE.Length=%d invalid (Raw=%d)", hdr.Length, len(c.Raw))
	}

	signed := c.Raw[8:hdr.Length]
	p7, err := pkcs7.Parse(signed)
	if err != nil {
		return nil, fmt.Errorf("cert: parse PKCS#7: %w", err)
	}

	// Defensive copy: pkcs7.Parse hands back its own internal
	// slice; callers mutating Certs would otherwise leak into the
	// parser's state. Anomalies / Raw already follow this pattern.
	certs := append([]*x509.Certificate(nil), p7.Certificates...)
	out := &ParsedAuthenticode{Header: hdr, Certs: certs}

	signer := p7.GetOnlySigner()
	if signer == nil {
		return out, ErrCertificateNoSigners
	}
	out.Signer = signer
	out.Issuer = signer.Issuer.String()
	out.Subject = signer.Subject.String()
	out.Serial = signer.SerialNumber
	out.NotBefore = signer.NotBefore
	out.NotAfter = signer.NotAfter
	out.Algorithm = signer.SignatureAlgorithm
	return out, nil
}
