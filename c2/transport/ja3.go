package transport

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

// JA3Profile identifies a TLS client fingerprint to mimic.
type JA3Profile int

const (
	// JA3Chrome mimics the latest Chrome TLS fingerprint.
	JA3Chrome JA3Profile = iota
	// JA3Firefox mimics the latest Firefox TLS fingerprint.
	JA3Firefox
	// JA3Edge mimics the latest Edge TLS fingerprint.
	JA3Edge
	// JA3Safari mimics the latest Safari TLS fingerprint.
	JA3Safari
	// JA3Go is the default Go TLS fingerprint (no spoofing).
	JA3Go
)

func (p JA3Profile) String() string {
	switch p {
	case JA3Chrome:
		return "Chrome"
	case JA3Firefox:
		return "Firefox"
	case JA3Edge:
		return "Edge"
	case JA3Safari:
		return "Safari"
	case JA3Go:
		return "Go (default)"
	default:
		return fmt.Sprintf("JA3Profile(%d)", p)
	}
}

// utlsClientHelloID maps JA3Profile to the uTLS ClientHelloID.
func (p JA3Profile) helloID() utls.ClientHelloID {
	switch p {
	case JA3Chrome:
		return utls.HelloChrome_Auto
	case JA3Firefox:
		return utls.HelloFirefox_Auto
	case JA3Edge:
		return utls.HelloEdge_Auto
	case JA3Safari:
		return utls.HelloSafari_Auto
	default:
		return utls.HelloGolang
	}
}

// UTLS implements Transport over TLS with JA3 fingerprint spoofing
// via uTLS. The TLS ClientHello is crafted to match a specific browser's
// fingerprint, making the connection indistinguishable from legitimate
// browser traffic to JA3/JA4-based network detection.
type UTLS struct {
	address     string
	timeout     time.Duration
	profile     JA3Profile
	sni         string // Server Name Indication (defaults to host from address)
	insecure    bool
	fingerprint string // cert pinning
	conn        net.Conn
}

// UTLSOption configures a UTLS.
type UTLSOption func(*UTLS)

// WithJA3Profile sets the browser profile to mimic.
func WithJA3Profile(p JA3Profile) UTLSOption {
	return func(t *UTLS) { t.profile = p }
}

// WithSNI sets a custom Server Name Indication (for domain fronting).
func WithSNI(sni string) UTLSOption {
	return func(t *UTLS) { t.sni = sni }
}

// WithUTLSInsecure disables server certificate verification.
func WithUTLSInsecure(insecure bool) UTLSOption {
	return func(t *UTLS) { t.insecure = insecure }
}

// WithUTLSFingerprint enables certificate pinning.
func WithUTLSFingerprint(fp string) UTLSOption {
	return func(t *UTLS) { t.fingerprint = fp }
}

// NewUTLS creates a new TLS transport with JA3 fingerprint spoofing.
// Default profile is JA3Chrome if not overridden via WithJA3Profile.
//
// Example:
//
//	t := transport.NewUTLS("10.0.0.1:443", 10*time.Second,
//	    transport.WithJA3Profile(transport.JA3Chrome),
//	    transport.WithUTLSInsecure(true),
//	)
func NewUTLS(address string, timeout time.Duration, opts ...UTLSOption) *UTLS {
	t := &UTLS{
		address: address,
		timeout: timeout,
		profile: JA3Chrome,
	}
	for _, opt := range opts {
		opt(t)
	}
	return t
}

// Connect establishes a TLS connection with the configured JA3 profile.
func (t *UTLS) Connect(ctx context.Context) error {
	if t.conn != nil {
		t.conn.Close()
		t.conn = nil
	}

	host, _, err := net.SplitHostPort(t.address)
	if err != nil {
		host = t.address
	}
	sni := t.sni
	if sni == "" {
		sni = host
	}

	dialer := &net.Dialer{Timeout: t.timeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", t.address)
	if err != nil {
		return fmt.Errorf("TCP dial: %w", err)
	}

	tlsConfig := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: t.insecure,
	}

	if t.fingerprint != "" {
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyFP(rawCerts, t.fingerprint)
		}
	}

	tlsConn := utls.UClient(rawConn, tlsConfig, t.profile.helloID())
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return fmt.Errorf("uTLS handshake (%s): %w", t.profile, err)
	}

	t.conn = tlsConn
	return nil
}

func (t *UTLS) Read(p []byte) (int, error) {
	if t.conn == nil {
		return 0, io.ErrClosedPipe
	}
	return t.conn.Read(p)
}

func (t *UTLS) Write(p []byte) (int, error) {
	if t.conn == nil {
		return 0, io.ErrClosedPipe
	}
	return t.conn.Write(p)
}

func (t *UTLS) Close() error {
	if t.conn == nil {
		return nil
	}
	return t.conn.Close()
}

func (t *UTLS) RemoteAddr() net.Addr {
	if t.conn == nil {
		return nil
	}
	return t.conn.RemoteAddr()
}
