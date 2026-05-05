package cert

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildSpcIndirectDataContent_RejectsEmptyDigest(t *testing.T) {
	_, err := BuildSpcIndirectDataContent(nil, crypto.SHA256)
	require.Error(t, err)
	_, err = BuildSpcIndirectDataContent([]byte{}, crypto.SHA256)
	require.Error(t, err)
}

func TestBuildSpcIndirectDataContent_RejectsUnknownHash(t *testing.T) {
	digest := bytes.Repeat([]byte{0x42}, 32)
	_, err := BuildSpcIndirectDataContent(digest, crypto.MD5)
	require.ErrorIs(t, err, ErrUnsupportedHash)
}

// TestBuildSpcIndirectDataContent_SHA256Roundtrip verifies the
// emitted ASN.1 round-trips: parse the DER bytes back into the
// same shape, confirm OID + digest reach the right slots.
func TestBuildSpcIndirectDataContent_SHA256Roundtrip(t *testing.T) {
	want := sha256.Sum256([]byte("test PE bytes"))
	der, err := BuildSpcIndirectDataContent(want[:], crypto.SHA256)
	require.NoError(t, err)
	require.NotEmpty(t, der)

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

	var got spcIndirectDataContent
	rest, err := asn1.Unmarshal(der, &got)
	require.NoError(t, err)
	assert.Empty(t, rest, "no trailing bytes")

	assert.True(t, got.Data.Type.Equal(OIDSpcPEImageDataObj),
		"SpcAttribute.Type must be SPC_PE_IMAGE_DATAOBJ_OBJID")
	assert.True(t, got.MessageDigest.DigestAlgorithm.Algorithm.Equal(OIDSHA256),
		"digestAlgorithm must be SHA-256")
	assert.Equal(t, want[:], got.MessageDigest.Digest,
		"digest must round-trip the input")
}

// TestHashOIDs_ExposedAsExpected guards the documented OIDs.
// Operators rely on these constants matching the Microsoft /
// RFC 5754 values exactly.
func TestHashOIDs_ExposedAsExpected(t *testing.T) {
	cases := []struct {
		name string
		got  asn1.ObjectIdentifier
		want asn1.ObjectIdentifier
	}{
		{"SpcIndirectDataContent", OIDSpcIndirectDataContent, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}},
		{"SpcPEImageDataObj", OIDSpcPEImageDataObj, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 15}},
		{"SHA1", OIDSHA1, asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}},
		{"SHA256", OIDSHA256, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}},
		{"SHA384", OIDSHA384, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}},
		{"SHA512", OIDSHA512, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.True(t, tc.got.Equal(tc.want),
				"%s: got=%v want=%v", tc.name, tc.got, tc.want)
		})
	}
}

func TestErrUnsupportedHash_IsSentinel(t *testing.T) {
	wrapped := errors.Join(ErrUnsupportedHash, errors.New("contextual"))
	assert.True(t, errors.Is(wrapped, ErrUnsupportedHash))
}
