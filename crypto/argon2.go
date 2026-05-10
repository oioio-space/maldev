package crypto

import (
	"fmt"

	"golang.org/x/crypto/argon2"
)

// Argon2id passphrase-to-key derivation. The 2015 Password Hashing
// Competition winner; the modern best-practice choice when an
// operator types a passphrase and the build pipeline needs a 32-byte
// AES key.
//
// Why Argon2id over alternatives:
//
//   - vs PBKDF2: Argon2id is memory-hard (configurable RAM cost),
//     so GPU/FPGA brute force scales linearly with memory cost.
//     PBKDF2 is purely time-hard — modern GPUs eat it.
//   - vs scrypt: Argon2id won the PHC; scrypt is the previous
//     generation. Practical security similar; Argon2id is the
//     standardized recommendation per RFC 9106 and OWASP.
//   - vs bcrypt: bcrypt fits passwords, not arbitrary key
//     derivation — output is a fixed 24 bytes and the salt is
//     baked in. Argon2id outputs any length.
//
// Two variants exposed:
//
//   - DeriveKeyFromPassword: sane build-host defaults (RFC 9106
//     recommendation B for memory-bound systems: 64 MiB RAM,
//     1 iteration, 4 threads). Build host runs on the operator's
//     workstation, not a target — expensive params are fine.
//   - DeriveKeyFromPasswordWithParams: full control for operators
//     wanting to tune (e.g. embedded build environments, faster
//     CI test loops).
//
// The derived key is intended for symmetric encryption — pair with
// EncryptAESGCM, EncryptChaCha20, or EncryptSpeck. For deriving
// MULTIPLE subkeys from a single passphrase, derive a master key
// here once, then use [DeriveKey] (HKDF) with per-purpose labels.

// Argon2idParams configures memory / time / parallelism for
// [DeriveKeyFromPasswordWithParams]. Zero values are illegal —
// every field must be non-zero (validated at call time).
type Argon2idParams struct {
	// Time is the number of iterations. RFC 9106 recommends 1 for
	// memory-bound, 3 for time-bound configurations.
	Time uint32
	// Memory is the memory cost in KiB. RFC 9106 recommendation B:
	// 64 * 1024 = 65_536 (64 MiB) for memory-bound systems.
	Memory uint32
	// Threads is the parallelism factor. RFC 9106: 4 is reasonable
	// for modern multi-core hosts; 1 for embedded.
	Threads uint8
}

// DefaultArgon2idParams returns the build-host-friendly defaults
// (RFC 9106 recommendation B, memory-bound). 64 MiB RAM, 1
// iteration, 4 threads. Tunable via [Argon2idParams] for callers
// with tighter resource budgets.
func DefaultArgon2idParams() Argon2idParams {
	return Argon2idParams{
		Time:    1,
		Memory:  64 * 1024,
		Threads: 4,
	}
}

// DeriveKeyFromPassword runs Argon2id with [DefaultArgon2idParams]
// to produce a length-byte key from password + salt. Use when the
// operator-typed passphrase is the master entropy source.
//
// Salt MUST be unique per deployment (operators committing the
// same salt across builds enable rainbow-table attacks). 16 bytes
// from [random.Bytes] is the canonical choice.
//
// Errors only on invalid input (empty password, salt < 8 bytes,
// length == 0). The Argon2 KDF itself never fails.
func DeriveKeyFromPassword(password, salt []byte, length uint32) ([]byte, error) {
	return DeriveKeyFromPasswordWithParams(password, salt, length, DefaultArgon2idParams())
}

// DeriveKeyFromPasswordWithParams is the full-control variant.
// Pass [DefaultArgon2idParams] when in doubt — those values pass
// the OWASP 2024 Argon2id verifier.
func DeriveKeyFromPasswordWithParams(password, salt []byte, length uint32, params Argon2idParams) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("crypto: argon2id password empty")
	}
	if len(salt) < 8 {
		return nil, fmt.Errorf("crypto: argon2id salt %d bytes < 8 (RFC 9106 minimum)", len(salt))
	}
	if length == 0 {
		return nil, fmt.Errorf("crypto: argon2id length 0")
	}
	if params.Time == 0 || params.Memory == 0 || params.Threads == 0 {
		return nil, fmt.Errorf("crypto: argon2id zero-valued params (got %+v)", params)
	}
	return argon2.IDKey(password, salt, params.Time, params.Memory, params.Threads, length), nil
}
