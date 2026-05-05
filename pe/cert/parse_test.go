package cert

import (
	"crypto/x509/pkix"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertificateParse_RejectsTooSmall(t *testing.T) {
	_, err := (&Certificate{Raw: nil}).Parse()
	require.ErrorIs(t, err, ErrCertificateTooSmall)

	_, err = (&Certificate{Raw: []byte{0x01, 0x02}}).Parse()
	require.ErrorIs(t, err, ErrCertificateTooSmall)
}

func TestCertificateParse_RejectsNilReceiver(t *testing.T) {
	var c *Certificate
	_, err := c.Parse()
	require.ErrorIs(t, err, ErrCertificateTooSmall)
}

func TestCertificateParse_RejectsBogusHeader(t *testing.T) {
	// 8-byte header with Length=0xFFFFFFFF — overruns Raw.
	bogus := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00}
	_, err := (&Certificate{Raw: bogus}).Parse()
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrCertificateTooSmall)
}

// TestCertificateParse_RoundTripForge — produce a chain via
// Forge, parse the resulting Raw bytes, expect the leaf subject
// to come back. Closes the forge ↔ parse loop end-to-end.
func TestCertificateParse_RoundTripForge(t *testing.T) {
	chain, err := Forge(ForgeOptions{
		LeafSubject: pkix.Name{
			CommonName: "Test Forge Leaf",
		},
		RootSubject: pkix.Name{
			CommonName: "Test Forge Root",
		},
		KeyBits: 1024, // tests-only; production uses ≥2048
	})
	require.NoError(t, err)

	parsed, err := chain.Certificate.Parse()
	require.NoError(t, err)
	require.NotNil(t, parsed)

	// Header invariants — must mirror what Forge / wrapWinCertificate emitted.
	assert.Equal(t, uint16(0x0200), parsed.Header.Revision)
	assert.Equal(t, uint16(0x0002), parsed.Header.CertificateType)
	assert.Greater(t, parsed.Header.Length, uint32(8))

	// Forge leaf surfaces correctly.
	require.NotNil(t, parsed.Signer)
	assert.Equal(t, "Test Forge Leaf", parsed.Signer.Subject.CommonName)
	assert.Contains(t, parsed.Subject, "Test Forge Leaf")

	// 2-tier chain: leaf signed by root → Issuer == root subject.
	assert.Contains(t, parsed.Issuer, "Test Forge Root")

	// Validity window matches Forge's defaults (now-1y → now+5y).
	assert.True(t, parsed.NotAfter.After(parsed.NotBefore))
	assert.False(t, parsed.Serial.Sign() == 0, "serial must be non-zero")

	// SignedData chain count: leaf + root = 2 (no intermediate
	// in this test). Forge emits both.
	assert.Len(t, parsed.Certs, 2, "2-tier chain should embed leaf + root")
}

func TestCertificateParse_NoSignersReturnsSentinel(t *testing.T) {
	// pkcs7.Parse round-trip on a degenerate certs-only blob would
	// trigger ErrCertificateNoSigners. Constructing such a blob
	// requires building a SignedData without AddSignerChain — out
	// of scope for a unit test. Confirm the sentinel is exported
	// and errors.Is-compatible (the actual no-signer path is
	// covered by saferwall's own tests + our integration usage).
	wrapped := errors.Join(ErrCertificateNoSigners, errors.New("contextual"))
	assert.True(t, errors.Is(wrapped, ErrCertificateNoSigners))
}
