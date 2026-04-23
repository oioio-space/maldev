package sleepmask

// Cipher is the symmetric transform the mask applies to each region
// before sleep and again on wake. Every bundled cipher is symmetric
// (XOR, RC4, AES-CTR) so a single Apply call serves as both encrypt
// and decrypt — the caller just invokes it twice around the wait.
//
// Implementations must:
//   - Be deterministic given (buf, key): calling Apply twice restores buf.
//   - Tolerate any buf length (including 0).
//   - Tolerate keys of exactly KeySize() bytes. If a key of a different
//     length is passed, the behavior is implementation-defined (XOR
//     accepts any non-empty size; the stream ciphers panic).
//
// Callers do not hold cipher state across cycles — a fresh random key
// is generated each Sleep, so each Apply pair is a self-contained
// transform. This is intentional: a leaked key from one cycle cannot
// decrypt another.
type Cipher interface {
	// KeySize returns the key length in bytes the cipher expects. The
	// mask uses this to size the per-cycle random buffer.
	KeySize() int

	// Apply transforms buf in place. Must be its own inverse when
	// called with the same key (symmetric cipher contract).
	Apply(buf, key []byte)
}
