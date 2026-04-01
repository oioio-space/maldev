package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"time"
)

// TLSTransport implements Transport over TLS with optional certificate pinning.
type TLSTransport struct {
	address     string
	timeout     time.Duration
	certPath    string
	keyPath     string
	insecure    bool
	fingerprint string
	conn        net.Conn
}

// TLSOption configures a TLSTransport.
type TLSOption func(*TLSTransport)

// WithInsecure disables server certificate verification.
func WithInsecure(insecure bool) TLSOption {
	return func(t *TLSTransport) {
		t.insecure = insecure
	}
}

// WithFingerprint enables certificate pinning via SHA256 fingerprint verification.
func WithFingerprint(fp string) TLSOption {
	return func(t *TLSTransport) {
		t.fingerprint = fp
	}
}

// NewTLSTransport creates a new TLS transport.
func NewTLSTransport(address string, timeout time.Duration, certPath, keyPath string, opts ...TLSOption) *TLSTransport {
	t := &TLSTransport{
		address:  address,
		timeout:  timeout,
		certPath: certPath,
		keyPath:  keyPath,
	}

	for _, opt := range opts {
		opt(t)
	}

	return t
}

// Connect establishes a TLS connection with optional client certificates
// and certificate pinning.
func (t *TLSTransport) Connect(ctx context.Context) error {
	var certificates []tls.Certificate
	if t.certPath != "" && t.keyPath != "" {
		cert, err := tls.LoadX509KeyPair(t.certPath, t.keyPath)
		if err != nil {
			return fmt.Errorf("failed to load client certificate: %w", err)
		}
		certificates = append(certificates, cert)
	}

	tlsConfig := &tls.Config{
		Certificates:       certificates,
		InsecureSkipVerify: t.insecure,
	}

	if t.fingerprint != "" && !t.insecure {
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return t.verifyFingerprint(rawCerts)
		}
	}

	dialer := &net.Dialer{
		Timeout: t.timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", t.address)
	if err != nil {
		return fmt.Errorf("TCP dial failed: %w", err)
	}

	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return fmt.Errorf("TLS handshake failed: %w", err)
	}

	t.conn = tlsConn
	return nil
}

// verifyFingerprint checks the server certificate against the pinned fingerprint.
func (t *TLSTransport) verifyFingerprint(rawCerts [][]byte) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("no certificates received")
	}

	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	if cert == nil {
		return fmt.Errorf("certificate parsing returned nil")
	}

	serverFingerprint := fmt.Sprintf("%X", cert.Raw)
	if serverFingerprint != t.fingerprint {
		return fmt.Errorf("certificate fingerprint mismatch")
	}

	return nil
}

// Read reads from the TLS connection.
func (t *TLSTransport) Read(p []byte) (int, error) {
	if t.conn == nil {
		return 0, io.ErrClosedPipe
	}
	return t.conn.Read(p)
}

// Write writes to the TLS connection.
func (t *TLSTransport) Write(p []byte) (int, error) {
	if t.conn == nil {
		return 0, io.ErrClosedPipe
	}
	return t.conn.Write(p)
}

// Close closes the TLS connection.
func (t *TLSTransport) Close() error {
	if t.conn == nil {
		return nil
	}
	return t.conn.Close()
}

// RemoteAddr returns the remote address.
func (t *TLSTransport) RemoteAddr() net.Addr {
	if t.conn == nil {
		return nil
	}
	return t.conn.RemoteAddr()
}
