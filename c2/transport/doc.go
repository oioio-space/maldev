// Package transport provides pluggable network transport implementations
// for C2 communication including plain TCP and TLS with certificate pinning.
//
// Platform: Cross-platform
// Detection: Medium -- TLS connections with self-signed certs may be flagged
// by network monitoring; certificate pinning defeats TLS inspection proxies.
//
// The Transport interface defines Connect, Read, Write, Close, and RemoteAddr
// methods. Two implementations are provided:
//   - TCPTransport: plain TCP connections with configurable timeout
//   - TLSTransport: TLS connections with optional client certificates,
//     InsecureSkipVerify, and SHA256 certificate fingerprint pinning
//
// The factory function New creates the appropriate transport from
// a Config struct based on the UseTLS flag.
package transport
