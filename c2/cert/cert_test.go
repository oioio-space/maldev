package cert

import (
	"crypto/tls"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateAndParse(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	cfg := DefaultConfig()
	// Use a smaller key size to keep the test fast.
	cfg.KeySize = 2048

	err := Generate(cfg, certPath, keyPath)
	require.NoError(t, err, "Generate should succeed")

	// Verify the output files form a valid TLS key pair.
	_, err = tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err, "LoadX509KeyPair should parse the generated cert/key")

	// On non-Windows platforms verify the key file is 0600.
	if runtime.GOOS != "windows" {
		info, statErr := os.Stat(keyPath)
		require.NoError(t, statErr)
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "key file must be 0600")
	}
}

func TestFingerprint(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	cfg := DefaultConfig()
	cfg.KeySize = 2048

	require.NoError(t, Generate(cfg, certPath, keyPath))

	fp, err := Fingerprint(certPath)
	require.NoError(t, err, "Fingerprint should succeed")

	assert.NotEmpty(t, fp, "fingerprint must not be empty")

	// Must be a valid upper-case hex string (Fingerprint uses %X).
	decoded, err := hex.DecodeString(fp)
	assert.NoError(t, err, "fingerprint must be a valid hex string")

	// SHA-256 produces 32 bytes → 64 hex characters.
	assert.Len(t, decoded, 32, "SHA-256 fingerprint must decode to 32 bytes")
	assert.Len(t, fp, 64, "SHA-256 fingerprint must be 64 hex characters")
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	require.NotNil(t, cfg)

	assert.NotEmpty(t, cfg.Organization, "Organization must not be empty")
	assert.Greater(t, cfg.KeySize, 0, "KeySize must be positive")
	assert.Greater(t, cfg.ValidDays, 0, "ValidDays must be positive")
}
