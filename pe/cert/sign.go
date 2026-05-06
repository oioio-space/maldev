package cert

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// PKCS#7 / CMS OIDs hand-rolled here (rather than imported from
// secDre4mer/pkcs7) so SignPE controls every byte of the resulting
// SignedData. The pkcs7 library hardcodes eContentType = OIDData;
// for real Authenticode we need OIDSpcIndirectDataContent there.
var (
	oidPKCS7SignedData   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidAttrContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttrMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidRSAEncryption     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
)

// algorithmIdentifier mirrors X.509 / CMS AlgorithmIdentifier.
type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// issuerAndSerial mirrors CMS IssuerAndSerialNumber. Issuer is
// the signer cert's RawIssuer (already DER) — re-encoding via
// pkix.Name loses ordering and breaks the issuerAndSerial match.
type issuerAndSerial struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

type signedAttribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type signerInfo struct {
	Version                   int
	IssuerAndSerialNumber     issuerAndSerial
	DigestAlgorithm           algorithmIdentifier
	AuthenticatedAttributes   asn1.RawValue `asn1:"optional,tag:0"`
	DigestEncryptionAlgorithm algorithmIdentifier
	EncryptedDigest           []byte
}

type encapContentInfo struct {
	EContentType asn1.ObjectIdentifier
	// EContent carries the [0] EXPLICIT wrapper baked into FullBytes
	// (derWrap(0xA0, octetString)). encoding/asn1 emits FullBytes
	// verbatim and ignores the asn1 struct tag, so the wrapping
	// MUST be pre-applied — the alternative (drop FullBytes, set
	// Bytes) loses the OCTET STRING tag we need at the inner layer.
	EContent asn1.RawValue `asn1:"optional"`
}

type signedDataInner struct {
	Version          int
	DigestAlgorithms []algorithmIdentifier `asn1:"set"`
	EncapContentInfo encapContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

type contentInfoOuter struct {
	ContentType asn1.ObjectIdentifier
	// Content carries the [0] EXPLICIT wrapper baked into FullBytes
	// (derWrap(0xA0, signedDataSequence)). Same reason as
	// encapContentInfo.EContent — RawValue.FullBytes bypasses
	// encoding/asn1's tag annotations.
	Content asn1.RawValue
}

// SignOptions tunes [SignPE]. The zero value is invalid — at minimum
// LeafSubject and RootSubject must be set (same contract as
// [ForgeOptions]). Validity, intermediate, and key size knobs all
// mirror ForgeOptions.
type SignOptions struct {
	LeafSubject         pkixName
	IntermediateSubject pkixName
	RootSubject         pkixName
	KeyBits             int
	ValidFrom, ValidTo  time.Time
}

// pkixName aliases pkix.Name so we don't widen the public import
// surface beyond what cert.ForgeOptions already exposes. Keep this
// internal alias unexported — operators stay on pkix.Name.
type pkixName = forgePkixName

// SignPE produces a real Authenticode-shaped SignedData over the
// PE at pePath, splices it into the security directory, and
// recomputes the optional-header CheckSum — same contract as
// [Write] but the signature carries the right
// `OIDSpcIndirectDataContent` outer ContentType + a leaf-key
// signature over the canonical signed attributes (contentType +
// messageDigest).
//
// The result IS structurally a valid Authenticode signature
// (signtool verify /v parses it without "couldn't decode" errors),
// but the chain root is self-signed → signtool verify /pa rejects
// "untrusted root". For a chain Windows trusts you need a real
// CA-issued leaf — that's the operational gap [Forge] / [SignPE]
// can't close in pure Go.
//
// Returns the [ForgedChain] (same shape as [Forge]) so callers can
// reuse the leaf key + chain across multiple PEs without paying
// the keygen cost twice.
func SignPE(pePath string, opts SignOptions) (*ForgedChain, error) {
	if opts.LeafSubject.CommonName == "" || opts.RootSubject.CommonName == "" {
		return nil, ErrInvalidForgeOptions
	}
	chain, err := Forge(ForgeOptions{
		LeafSubject:         opts.LeafSubject,
		IntermediateSubject: opts.IntermediateSubject,
		RootSubject:         opts.RootSubject,
		KeyBits:             opts.KeyBits,
		ValidFrom:           opts.ValidFrom,
		ValidTo:             opts.ValidTo,
	})
	if err != nil {
		return nil, fmt.Errorf("SignPE: forge chain: %w", err)
	}

	content, err := AuthenticodeContent(pePath)
	if err != nil {
		return nil, fmt.Errorf("SignPE: %w", err)
	}

	signed, err := buildAuthenticodeSignedData(content, chain)
	if err != nil {
		return nil, fmt.Errorf("SignPE: build SignedData: %w", err)
	}
	wrapped := wrapWinCertificate(signed)
	if err := Write(pePath, wrapped); err != nil {
		return nil, fmt.Errorf("SignPE: splice: %w", err)
	}
	chain.Certificate = wrapped
	return chain, nil
}

// buildAuthenticodeSignedData hand-rolls the PKCS#7 SignedData
// blob — eContentType = OIDSpcIndirectDataContent, signed attrs
// = contentType + messageDigest, leaf-key RSA-SHA256 signature
// over the canonical attrs DER.
func buildAuthenticodeSignedData(spcContent []byte, chain *ForgedChain) ([]byte, error) {
	// SpcIndirectDataContent body: skip outer SEQUENCE tag+length so
	// messageDigest covers only the content bytes (Authenticode spec).
	body, err := spcIndirectContentBytes(spcContent)
	if err != nil {
		return nil, fmt.Errorf("extract SpcIndirectDataContent body: %w", err)
	}
	bodyDigest := sha256.Sum256(body)

	// Build each Attribute.Value as a SET. encoding/asn1 default for
	// a slice is SEQUENCE, so retag the outer 0x30 to 0x31.
	contentTypeAttrValue, err := asn1.Marshal([]asn1.ObjectIdentifier{OIDSpcIndirectDataContent})
	if err != nil {
		return nil, err
	}
	messageDigestAttrValue, err := asn1.Marshal([][]byte{bodyDigest[:]})
	if err != nil {
		return nil, err
	}
	contentTypeAttrValue[0] = 0x31
	messageDigestAttrValue[0] = 0x31

	signedAttrs := []signedAttribute{
		{Type: oidAttrContentType, Value: asn1.RawValue{FullBytes: contentTypeAttrValue}},
		{Type: oidAttrMessageDigest, Value: asn1.RawValue{FullBytes: messageDigestAttrValue}},
	}

	// Encode signed attributes twice: once as [0] IMPLICIT SET for
	// the wire (what goes into AuthenticatedAttributes), once as
	// universal SET for the digest+signature. Per CMS §5.4 the
	// signature is over the SET-tagged form, not the [0] form.
	implicitSetBytes, err := marshalSignedAttrsImplicitSet(signedAttrs)
	if err != nil {
		return nil, err
	}
	universalSetBytes := append([]byte{0x31}, implicitSetBytes[1:]...) // 0xA0 → 0x31
	attrsDigest := sha256.Sum256(universalSetBytes)

	signature, err := rsa.SignPKCS1v15(nil, chain.LeafKey, crypto.SHA256, attrsDigest[:])
	if err != nil {
		return nil, fmt.Errorf("sign attrs: %w", err)
	}

	si := signerInfo{
		Version: 1,
		IssuerAndSerialNumber: issuerAndSerial{
			Issuer:       asn1.RawValue{FullBytes: chain.Leaf.RawIssuer},
			SerialNumber: chain.Leaf.SerialNumber,
		},
		DigestAlgorithm:           algorithmIdentifier{Algorithm: OIDSHA256, Parameters: asn1.NullRawValue},
		AuthenticatedAttributes:   asn1.RawValue{FullBytes: implicitSetBytes},
		DigestEncryptionAlgorithm: algorithmIdentifier{Algorithm: oidRSAEncryption, Parameters: asn1.NullRawValue},
		EncryptedDigest:           signature,
	}

	certsBytes, err := encodeCertChain(chain)
	if err != nil {
		return nil, err
	}

	inner := signedDataInner{
		Version: 1,
		DigestAlgorithms: []algorithmIdentifier{
			{Algorithm: OIDSHA256, Parameters: asn1.NullRawValue},
		},
		EncapContentInfo: encapContentInfo{
			EContentType: OIDSpcIndirectDataContent,
			// Authenticode deviates from RFC 5652: eContent is NOT
			// wrapped in OCTET STRING. The [0] EXPLICIT directly
			// contains the SpcIndirectDataContent SEQUENCE.
			EContent: asn1.RawValue{FullBytes: derWrap(0xA0, spcContent)},
		},
		Certificates: asn1.RawValue{FullBytes: certsBytes},
		SignerInfos:  []signerInfo{si},
	}
	innerBytes, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("marshal SignedData: %w", err)
	}

	outer := contentInfoOuter{
		ContentType: oidPKCS7SignedData,
		Content:     asn1.RawValue{FullBytes: derWrap(0xA0, innerBytes)},
	}
	return asn1.Marshal(outer)
}

// marshalSignedAttrsImplicitSet emits the signed attributes as
// `[0] IMPLICIT SET OF Attribute` — the on-the-wire form for
// signerInfo.AuthenticatedAttributes.
func marshalSignedAttrsImplicitSet(attrs []signedAttribute) ([]byte, error) {
	// Marshal as a regular SET OF Attribute, then patch the outer tag
	// from 0x31 (universal SET) to 0xA0 ([0] IMPLICIT context-specific,
	// constructed).
	setDER, err := asn1.Marshal(struct {
		Items []signedAttribute `asn1:"set"`
	}{Items: attrs})
	if err != nil {
		return nil, err
	}
	// asn1.Marshal wraps in an outer SEQUENCE for the struct — peel
	// it: SEQUENCE { SET { ... } } → SET { ... }
	inner, err := asn1Skip(setDER, 0x30) // skip outer SEQUENCE
	if err != nil {
		return nil, err
	}
	out := append([]byte{0xA0}, inner[1:]...) // 0x31 → 0xA0
	return out, nil
}

// asn1Skip verifies the leading tag byte and returns the slice
// starting at the SAME byte (not advanced past tag) — used to
// retag IMPLICIT contexts.
func asn1Skip(buf []byte, wantTag byte) ([]byte, error) {
	if len(buf) == 0 || buf[0] != wantTag {
		return nil, fmt.Errorf("asn1Skip: expected tag 0x%02x, got 0x%02x", wantTag, buf[0])
	}
	// Parse length to skip header.
	if buf[1]&0x80 == 0 {
		return buf[2:], nil
	}
	lenBytes := int(buf[1] & 0x7f)
	return buf[2+lenBytes:], nil
}

// spcIndirectContentBytes returns the SpcIndirectDataContent's
// inner content octets (skipping the outer SEQUENCE tag + length).
// Per Authenticode spec, the messageDigest attribute hashes these
// bytes, NOT the full DER.
func spcIndirectContentBytes(spcDER []byte) ([]byte, error) {
	if len(spcDER) < 2 || spcDER[0] != 0x30 {
		return nil, errors.New("not a SpcIndirectDataContent SEQUENCE")
	}
	if spcDER[1]&0x80 == 0 {
		return spcDER[2:], nil
	}
	lenBytes := int(spcDER[1] & 0x7f)
	return spcDER[2+lenBytes:], nil
}

// encodeCertChain emits `[0] IMPLICIT SET OF Certificate` — the
// SignedData.certificates field. The chain ordering follows the
// SignedData convention: leaf, then any intermediates, then root.
func encodeCertChain(chain *ForgedChain) ([]byte, error) {
	var concat []byte
	concat = append(concat, chain.Leaf.Raw...)
	if chain.Intermediate != nil {
		concat = append(concat, chain.Intermediate.Raw...)
	}
	if chain.Root != nil {
		concat = append(concat, chain.Root.Raw...)
	}
	// Wrap in [0] IMPLICIT (tag 0xA0, constructed) with DER length.
	return derWrap(0xA0, concat), nil
}

// derWrap prepends a tag + length to `payload`. Long-form length
// encoding follows DER: short for <128, long for ≥128.
func derWrap(tag byte, payload []byte) []byte {
	header := []byte{tag}
	n := len(payload)
	switch {
	case n < 0x80:
		header = append(header, byte(n))
	case n < 0x100:
		header = append(header, 0x81, byte(n))
	case n < 0x10000:
		header = append(header, 0x82, byte(n>>8), byte(n))
	case n < 0x1000000:
		header = append(header, 0x83, byte(n>>16), byte(n>>8), byte(n))
	default:
		header = append(header, 0x84, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	out := make([]byte, 0, len(header)+n)
	out = append(out, header...)
	out = append(out, payload...)
	return out
}

// forgePkixName aliases pkix.Name so SignOptions reads with the
// same public-surface convention as ForgeOptions.
type forgePkixName = pkix.Name
