package crypto

import "github.com/oioio-space/maldev/cleanup/memory"

// Wipe zeros the byte slice using the same compiler-resistant memclear
// as cleanup/memory.SecureZero. Convenience re-export for the common
// payload-ephemeral pattern:
//
//	plaintext, err := crypto.DecryptAESGCM(key, ct)
//	if err != nil {
//	    return err
//	}
//	defer crypto.Wipe(plaintext)
//
// EDR memory scans sweep RW pages between syscalls — wipe before the
// next syscall, not after. Use UseDecrypted when the scoping fits.
func Wipe(buf []byte) { memory.SecureZero(buf) }

// UseDecrypted runs decrypt, hands the resulting plaintext to fn, and
// wipes the plaintext buffer before returning. The wipe runs via defer
// so it executes even when fn returns an error or panics.
//
// Callers MUST NOT retain a reference to the slice fn receives; the
// underlying bytes are zeroed before UseDecrypted returns. Copy what
// must outlive the helper.
//
// Typical usage with the package's AEAD primitives:
//
//	err := crypto.UseDecrypted(
//	    func() ([]byte, error) { return crypto.DecryptAESGCM(key, ct) },
//	    func(plaintext []byte) error {
//	        return inject.SectionMapInject(pid, plaintext, caller)
//	    },
//	)
//
// decrypt is a closure rather than a typed function so any decrypt
// shape (fixed-size keys for TEA/XTEA, additional AAD for AEAD, etc.)
// fits without per-cipher overloads.
func UseDecrypted(decrypt func() ([]byte, error), fn func([]byte) error) error {
	plaintext, err := decrypt()
	if err != nil {
		return err
	}
	defer Wipe(plaintext)
	return fn(plaintext)
}
