// Package crypto provides cryptographic primitives for payload encryption and
// decryption including AES, RC4, and XOR ciphers.
//
// Platform: Cross-platform
// Detection: N/A -- pure cryptographic utilities with no system interaction.
//
// These functions are intended for encrypting/decrypting shellcode and other
// payloads at rest or in transit. They do not touch disk or make syscalls.
package crypto
