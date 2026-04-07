package transport

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
)

// verifyFP checks the first server certificate against a SHA256 fingerprint.
// Shared by TLS and UTLS for certificate pinning.
func verifyFP(rawCerts [][]byte, expected string) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("no certificates received")
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}
	hash := sha256.Sum256(cert.Raw)
	got := fmt.Sprintf("%X", hash[:])
	if got != expected {
		return fmt.Errorf("certificate fingerprint mismatch")
	}
	return nil
}
