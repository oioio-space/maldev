package cert_test

import (
	"crypto/sha256"
	"encoding/asn1"
	"os"
	"runtime"
	"testing"

	"github.com/oioio-space/maldev/pe/cert"
)

// signedDonorPath returns a Windows path to a PE that has an
// embedded Authenticode signature on the standard test box. Skips
// the test on non-Windows + when the file is missing.
func signedDonorPath(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		t.Skip("requires Windows for embedded-signed donor PE")
	}
	candidates := []string{
		`C:\Windows\System32\drivers\etc\..\..\WindowsPowerShell\v1.0\powershell.exe`,
		`C:\Program Files\Mozilla Firefox\firefox.exe`,
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("no signed donor PE available on this host")
	return ""
}

func TestAuthenticodeContent_ProducesParseableSpcIndirectDataContent(t *testing.T) {
	pePath := signedDonorPath(t)

	content, err := cert.AuthenticodeContent(pePath)
	if err != nil {
		t.Fatalf("AuthenticodeContent: %v", err)
	}
	if len(content) < 50 {
		t.Fatalf("content too small (%d bytes)", len(content))
	}

	// Round-trip parse: SpcIndirectDataContent is a SEQUENCE; the
	// outer DER tag must be 0x30. The inner messageDigest's algorithm
	// OID must round-trip to the SHA-256 OID.
	if content[0] != 0x30 {
		t.Errorf("expected outer SEQUENCE tag 0x30, got 0x%02x", content[0])
	}

	var decoded struct {
		Data struct {
			Type  asn1.ObjectIdentifier
			Value asn1.RawValue
		}
		MessageDigest struct {
			DigestAlgorithm struct {
				Algorithm  asn1.ObjectIdentifier
				Parameters asn1.RawValue `asn1:"optional"`
			}
			Digest []byte
		}
	}
	if _, err := asn1.Unmarshal(content, &decoded); err != nil {
		t.Fatalf("decode SpcIndirectDataContent: %v", err)
	}
	if !decoded.Data.Type.Equal(cert.OIDSpcPEImageDataObj) {
		t.Errorf("Data.Type = %v, want SpcPEImageDataObj", decoded.Data.Type)
	}
	if !decoded.MessageDigest.DigestAlgorithm.Algorithm.Equal(cert.OIDSHA256) {
		t.Errorf("DigestAlgorithm = %v, want SHA-256", decoded.MessageDigest.DigestAlgorithm.Algorithm)
	}
	if got := len(decoded.MessageDigest.Digest); got != sha256.Size {
		t.Errorf("Digest len = %d, want %d (SHA-256)", got, sha256.Size)
	}
}

func TestAuthenticodeContent_MissingPathErrors(t *testing.T) {
	_, err := cert.AuthenticodeContent("does-not-exist.exe")
	if err == nil {
		t.Fatal("expected error for missing path, got nil")
	}
}
