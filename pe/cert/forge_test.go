package cert

import (
	"crypto/x509/pkix"
	"encoding/binary"
	"testing"
	"time"

	"github.com/secDre4mer/pkcs7"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// minimalOpts returns a ForgeOptions with just enough fields to make
// Forge succeed. KeyBits=1024 is INSECURE for production use —
// crypto/rsa accepts but warns, and Go 1.24+ rejects sub-1024.
// Production callers must use the package default (2048+).
func minimalOpts() ForgeOptions {
	return ForgeOptions{
		LeafSubject: pkix.Name{
			CommonName:   "Microsoft Corporation",
			Organization: []string{"Microsoft Corporation"},
		},
		RootSubject: pkix.Name{
			CommonName: "Microsoft Root Certificate Authority",
		},
		KeyBits: 1024, // ~5x faster than the production default; tests only
	}
}

func TestForge_RejectsMissingLeafSubject(t *testing.T) {
	opts := minimalOpts()
	opts.LeafSubject = pkix.Name{}
	_, err := Forge(opts)
	require.ErrorIs(t, err, ErrInvalidForgeOptions)
}

func TestForge_RejectsMissingRootSubject(t *testing.T) {
	opts := minimalOpts()
	opts.RootSubject = pkix.Name{}
	_, err := Forge(opts)
	require.ErrorIs(t, err, ErrInvalidForgeOptions)
}

// TestForge_TwoTierChain_Invariants builds ONE chain and asserts
// every two-tier invariant in subtests. Saves ~250ms vs. five
// independent Forge calls.
func TestForge_TwoTierChain_Invariants(t *testing.T) {
	chain, err := Forge(minimalOpts())
	require.NoError(t, err)
	require.NotNil(t, chain)
	require.NotNil(t, chain.Certificate)

	t.Run("leaf+root populated", func(t *testing.T) {
		require.NotNil(t, chain.Leaf)
		require.NotNil(t, chain.Root)
	})
	t.Run("no intermediate when subject empty", func(t *testing.T) {
		assert.Nil(t, chain.Intermediate)
		assert.Nil(t, chain.IntermediateKey)
	})
	t.Run("subjects round-trip", func(t *testing.T) {
		assert.Equal(t, "Microsoft Corporation", chain.Leaf.Subject.CommonName)
		assert.Equal(t, "Microsoft Root Certificate Authority", chain.Root.Subject.CommonName)
	})
	t.Run("root is self-signed CA", func(t *testing.T) {
		assert.Equal(t, chain.Root.Subject.CommonName, chain.Root.Issuer.CommonName,
			"Issuer must equal Subject for a self-signed cert")
		assert.True(t, chain.Root.IsCA)
	})
	t.Run("default validity window", func(t *testing.T) {
		now := time.Now()
		// Defaults: NotBefore ≈ now - 1y, NotAfter ≈ now + 5y.
		// 1 hour slack absorbs test execution time.
		assert.WithinDuration(t, now.Add(-365*24*time.Hour), chain.Leaf.NotBefore, time.Hour)
		assert.WithinDuration(t, now.Add(5*365*24*time.Hour), chain.Leaf.NotAfter, time.Hour)
	})
	t.Run("WIN_CERTIFICATE header", func(t *testing.T) {
		raw := chain.Certificate.Raw
		require.GreaterOrEqual(t, len(raw), 8)
		dwLength := binary.LittleEndian.Uint32(raw[0:4])
		assert.LessOrEqual(t, int(dwLength), len(raw))
		assert.Greater(t, int(dwLength), 8)
		assert.Equal(t, uint16(0x0200), binary.LittleEndian.Uint16(raw[4:6]),
			"wRevision must be WIN_CERT_REVISION_2_0")
		assert.Equal(t, uint16(0x0002), binary.LittleEndian.Uint16(raw[6:8]),
			"wCertificateType must be WIN_CERT_TYPE_PKCS_SIGNED_DATA")
	})
	t.Run("Raw is 8-byte aligned", func(t *testing.T) {
		assert.Zero(t, len(chain.Certificate.Raw)%8,
			"WIN_CERTIFICATE bytes must be 8-byte aligned per PE spec")
	})
}

func TestForge_ThreeTierChain_WithIntermediate(t *testing.T) {
	opts := minimalOpts()
	opts.IntermediateSubject = pkix.Name{CommonName: "Microsoft Code Signing PCA"}

	chain, err := Forge(opts)
	require.NoError(t, err)
	require.NotNil(t, chain.Intermediate)
	require.NotNil(t, chain.IntermediateKey)
	assert.Equal(t, "Microsoft Code Signing PCA", chain.Intermediate.Subject.CommonName)

	// Issuer chain: Leaf.Issuer == Intermediate.Subject;
	// Intermediate.Issuer == Root.Subject;
	// Root.Issuer == Root.Subject (self-signed).
	assert.Equal(t, chain.Intermediate.Subject.CommonName, chain.Leaf.Issuer.CommonName)
	assert.Equal(t, chain.Root.Subject.CommonName, chain.Intermediate.Issuer.CommonName)
	assert.Equal(t, chain.Root.Subject.CommonName, chain.Root.Issuer.CommonName)
}

func TestForge_SignedDataParsesAndCarriesChain(t *testing.T) {
	opts := minimalOpts()
	opts.IntermediateSubject = pkix.Name{CommonName: "Forge Test Intermediate"}
	chain, err := Forge(opts)
	require.NoError(t, err)

	// Skip the WIN_CERTIFICATE header (8 bytes) + trim padding.
	dwLength := binary.LittleEndian.Uint32(chain.Certificate.Raw[0:4])
	signedBytes := chain.Certificate.Raw[8:dwLength]

	p7, err := pkcs7.Parse(signedBytes)
	require.NoError(t, err)
	require.NotNil(t, p7)
	assert.Len(t, p7.Certificates, 3,
		"SignedData must carry the full leaf+intermediate+root chain")

	var leafFound bool
	for _, c := range p7.Certificates {
		if c.Subject.CommonName == "Microsoft Corporation" {
			leafFound = true
			break
		}
	}
	assert.True(t, leafFound, "SignedData chain must include the leaf cert")
}

// TestForge_DefaultKeyBitsApplied catches a regression where the
// KeyBits=0 default branch is removed. Slow (2048-bit keygen) so
// gated under -short.
func TestForge_DefaultKeyBitsApplied(t *testing.T) {
	if testing.Short() {
		t.Skip("2048-bit keygen is slow; skip under -short")
	}
	opts := minimalOpts()
	opts.KeyBits = 0
	chain, err := Forge(opts)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, chain.LeafKey.N.BitLen(), 2000,
		"default KeyBits must be at least 2000 bits")
	// Two-tier shape sanity-check on the slow path.
	assert.Nil(t, chain.Intermediate)
}
