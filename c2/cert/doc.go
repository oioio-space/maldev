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
//
// How it works: C2 channels typically use TLS to encrypt traffic and avoid
// content-based detection. Self-signed certificates are generated at build or
// deploy time so that each operation uses a unique certificate, preventing
// signature-based blocklisting. The fingerprint function computes a SHA256
// hash of the certificate, which the implant can pin to ensure it only
// connects to the legitimate operator server and not a TLS interception proxy.
package cert
