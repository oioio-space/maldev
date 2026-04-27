package cert_test

import (
	"fmt"

	"github.com/oioio-space/maldev/c2/cert"
)

// Generate creates a self-signed X.509 cert + key in PEM. Used to
// stand up a local TLS listener for the operator side or a
// throw-away mTLS handshake.
func ExampleGenerate() {
	cfg := &cert.Config{
		CommonName:   "example.com",
		Organization: "Acme",
	}
	if err := cert.Generate(cfg, "/tmp/cert.pem", "/tmp/key.pem"); err != nil {
		fmt.Println("generate:", err)
	}
}

// Fingerprint returns the SHA-256 fingerprint of a PEM cert. Use it
// to pin a server cert in a TLS transport config.
func ExampleFingerprint() {
	fp, err := cert.Fingerprint("/tmp/cert.pem")
	if err != nil {
		fmt.Println("fp:", err)
		return
	}
	fmt.Println(fp)
}
