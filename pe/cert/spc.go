package cert

import (
	"crypto"
	"encoding/asn1"
	"errors"
	"fmt"
)

// Microsoft-defined Authenticode OIDs (winnt.h / wintrust.h).
//
//   - SPC_INDIRECT_DATA_OBJID (1.3.6.1.4.1.311.2.1.4) is the
//     PKCS#7 ContentInfo.contentType for an Authenticode-signed
//     blob — every signtool-verifiable PE / MSI / CAB carries
//     this OID at the outer SignedData layer.
//   - SPC_PE_IMAGE_DATAOBJ_OBJID (1.3.6.1.4.1.311.2.1.15) is the
//     SpcAttributeTypeAndOptionalValue.type for a PE image — tells
//     verifiers "the digest below was computed over a PE per the
//     Authenticode spec".
//   - The hash-algorithm OIDs match the standard X.509 / RFC 5754
//     identifiers so PKCS#7 verifiers route on them transparently.
var (
	OIDSpcIndirectDataContent = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}
	OIDSpcPEImageDataObj      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 15}
	OIDSHA1                   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	OIDSHA256                 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDSHA384                 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDSHA512                 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// ErrUnsupportedHash is returned by [BuildSpcIndirectDataContent]
// when the supplied hash function has no known Authenticode OID.
var ErrUnsupportedHash = errors.New("cert: hash algorithm has no known Authenticode OID (SHA1 / SHA256 / SHA384 / SHA512 only)")

// BuildSpcIndirectDataContent returns the ASN.1 DER encoding of
// the canonical Authenticode signed-content blob (the Go types
// declared inside the function mirror Microsoft's
// SpcIndirectDataContent ASN.1 spec verbatim).
//
// `digest` MUST be the PE's Authenticode hash (typically obtained
// via [github.com/oioio-space/maldev/pe/parse.File.Authentihash]).
// `hashAlg` selects the algorithm OID — SHA-256 is the modern
// default; SHA-1 is legacy-only.
//
// The output is the SECOND argument to a PKCS#7 SignedData
// `EncapsulatedContentInfo` whose `eContentType` is
// [OIDSpcIndirectDataContent]. Wrapping the bytes into a complete
// PKCS#7 SignedData is the next phase — `secDre4mer/pkcs7` doesn't
// expose an OID-override surface, so a future [ForgeForPE] entry
// point will hand-roll the outer SignedData around the leaf key
// produced by [Forge].
//
// Even without the outer SignedData wrapping, the bytes returned
// here are useful as a verifier-input fixture: feed them to a
// captured cert's `messageDigest` signed attribute via openssl /
// signtool to reproduce the canonical signing input.
func BuildSpcIndirectDataContent(digest []byte, hashAlg crypto.Hash) ([]byte, error) {
	algOID, err := authenticodeHashOID(hashAlg)
	if err != nil {
		return nil, err
	}
	if len(digest) == 0 {
		return nil, fmt.Errorf("cert: empty digest")
	}

	// The SpcAttributeTypeAndOptionalValue.value uses an
	// `[0] EXPLICIT ANY OPTIONAL` slot. Microsoft's reference
	// emits a SpcPEImageData containing flags + a SpcLink set to
	// the SpcString "<<<Obsolete>>>"; verifiers route on the
	// OID + digest, not the inner field, so we encode it as an
	// ASN.1 NULL — universally accepted, minimal byte cost,
	// round-trips cleanly through encoding/asn1.
	type algorithmIdentifier struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue `asn1:"optional"`
	}
	type digestInfo struct {
		DigestAlgorithm algorithmIdentifier
		Digest          []byte
	}
	type spcAttribute struct {
		Type  asn1.ObjectIdentifier
		Value asn1.RawValue `asn1:"optional"`
	}
	type spcIndirectDataContent struct {
		Data          spcAttribute
		MessageDigest digestInfo
	}

	content := spcIndirectDataContent{
		Data: spcAttribute{
			Type:  OIDSpcPEImageDataObj,
			Value: asn1.NullRawValue,
		},
		MessageDigest: digestInfo{
			DigestAlgorithm: algorithmIdentifier{
				Algorithm:  algOID,
				Parameters: asn1.NullRawValue,
			},
			Digest: digest,
		},
	}
	return asn1.Marshal(content)
}

// authenticodeHashOID maps a crypto.Hash to its Authenticode OID.
// Returns ErrUnsupportedHash for anything outside SHA1/256/384/512.
func authenticodeHashOID(h crypto.Hash) (asn1.ObjectIdentifier, error) {
	switch h {
	case crypto.SHA1:
		return OIDSHA1, nil
	case crypto.SHA256:
		return OIDSHA256, nil
	case crypto.SHA384:
		return OIDSHA384, nil
	case crypto.SHA512:
		return OIDSHA512, nil
	default:
		return nil, ErrUnsupportedHash
	}
}
