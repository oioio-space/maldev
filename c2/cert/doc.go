// Package cert provides self-signed X.509 certificate generation and
// fingerprint computation for C2 TLS infrastructure.
//
// Platform: Cross-platform
// Detection: Low -- certificate generation itself is benign.
//
// Key features:
//   - Generate: create a self-signed certificate and RSA private key in PEM format
//   - Fingerprint: compute hex-encoded fingerprint of a PEM certificate for pinning
//   - Configurable organization, common name, validity period, and key size
//
// Generated certificates include both ServerAuth and ClientAuth extended key usage,
// suitable for mutual TLS authentication between implant and handler.
package cert
