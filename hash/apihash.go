package hash

import "hash/crc32"

// API-hashing alternatives to ROR13 (`ror13.go`). Each function is a
// pure-Go single-pass byte hash suitable for converting a Windows
// function or module name into a uint32/uint64 fingerprint at
// build time. The PEB walker in `win/api` then iterates exports,
// hashing each name with the same function until it matches.
//
// Why ship more than one: signature engines that key on ROR13
// constants (e.g., the canonical 0x6A4ABC5B / 0x4FC8BB5A pair for
// kernel32 / LoadLibraryA) miss every other family. Operators
// pick a less-fingerprinted family — or hand-roll a custom
// HashFunc — and pair it with [`win/syscall`].`HashGate.WithHashFunc`.
//
// See docs/techniques/syscalls/api-hashing.md for the integration
// pattern.

// FNV1a32 returns the 32-bit FNV-1a hash of `name`. Reference
// implementation; matches `hash/fnv.New32a()` byte-for-byte but
// inlined so callers can compute the constant at build time
// without paying the allocation cost.
func FNV1a32(name string) uint32 {
	const (
		offset uint32 = 2166136261
		prime  uint32 = 16777619
	)
	h := offset
	for i := 0; i < len(name); i++ {
		h ^= uint32(name[i])
		h *= prime
	}
	return h
}

// FNV1a64 returns the 64-bit FNV-1a hash of `name`. Same shape as
// [FNV1a32] with the canonical 64-bit offset basis and prime.
func FNV1a64(name string) uint64 {
	const (
		offset uint64 = 14695981039346656037
		prime  uint64 = 1099511628211
	)
	h := offset
	for i := 0; i < len(name); i++ {
		h ^= uint64(name[i])
		h *= prime
	}
	return h
}

// JenkinsOAAT returns the Bob Jenkins one-at-a-time hash of `name`
// with the standard avalanche tail.
//
// Used by [`metaspace`-style shellcodes] that prefer Jenkins for
// the slightly better avalanche behaviour vs ROR13 on short
// strings. Cheap on amd64 (no division, no table).
//
// [`metaspace`-style shellcodes]: https://burnes.io/posts/jenkins-oaat-api-hashing/
func JenkinsOAAT(name string) uint32 {
	var h uint32
	for i := 0; i < len(name); i++ {
		h += uint32(name[i])
		h += h << 10
		h ^= h >> 6
	}
	h += h << 3
	h ^= h >> 11
	h += h << 15
	return h
}

// DJB2 returns the classic Bernstein hash (`hash * 33 + c`).
// Bias: not great on short inputs (collisions on small alphabets);
// kept here for parity with public-shellcode codebases that
// expect this constant set.
func DJB2(name string) uint32 {
	h := uint32(5381)
	for i := 0; i < len(name); i++ {
		h = h*33 + uint32(name[i])
	}
	return h
}

// CRC32 returns the IEEE polynomial CRC-32 of `name`. Backed by
// `hash/crc32`'s table-driven implementation (constant-time
// allocation; the table itself is computed once at process start).
//
// Useful when the operator wants a hash family that's also
// cryptographic-adjacent (CRC tables are everywhere; ROR13 is
// distinctively malware-shaped).
func CRC32(name string) uint32 {
	return crc32.ChecksumIEEE([]byte(name))
}
