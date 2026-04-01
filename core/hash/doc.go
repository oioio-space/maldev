// Package hash provides hashing utilities for integrity verification and
// API hashing including MD5, SHA-256, and DJB2 hash functions.
//
// Platform: Cross-platform
// Detection: N/A -- pure hashing utilities with no system interaction.
//
// API hashing (DJB2, CRC32) can be used to resolve Windows API functions
// at runtime without embedding plaintext function names, defeating static
// analysis of import tables.
package hash
