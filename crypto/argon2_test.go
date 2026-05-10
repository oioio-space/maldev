package crypto_test

import (
	"bytes"
	"testing"

	"github.com/oioio-space/maldev/crypto"
)

// cheapParams keeps the unit test fast — production callers should
// use [crypto.DefaultArgon2idParams] (64 MiB / 1 / 4 ≈ 60 ms on
// a modern x86_64).
var cheapParams = crypto.Argon2idParams{Time: 1, Memory: 8 * 1024, Threads: 1}

// TestDeriveKeyFromPassword_Deterministic asserts the basic contract:
// (password, salt, length) → same key every time.
func TestDeriveKeyFromPassword_Deterministic(t *testing.T) {
	password := []byte("operator-passphrase-2026")
	salt := []byte("uniqueperdeploy") // 15 bytes ≥ 8 minimum

	a, err := crypto.DeriveKeyFromPasswordWithParams(password, salt, 32, cheapParams)
	if err != nil {
		t.Fatalf("DeriveKeyFromPasswordWithParams: %v", err)
	}
	b, err := crypto.DeriveKeyFromPasswordWithParams(password, salt, 32, cheapParams)
	if err != nil {
		t.Fatalf("DeriveKeyFromPasswordWithParams: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("non-deterministic output for same inputs:\n  %x\n  %x", a, b)
	}
	if len(a) != 32 {
		t.Errorf("len(out) = %d, want 32", len(a))
	}
}

// TestDeriveKeyFromPassword_DifferentSaltsDifferentKeys catches
// "salt parameter ignored" regressions. Same passphrase + 2
// different salts must produce different keys.
func TestDeriveKeyFromPassword_DifferentSaltsDifferentKeys(t *testing.T) {
	password := []byte("p")
	saltA := []byte("aaaaaaaaaa")
	saltB := []byte("bbbbbbbbbb")
	a, _ := crypto.DeriveKeyFromPasswordWithParams(password, saltA, 32, cheapParams)
	b, _ := crypto.DeriveKeyFromPasswordWithParams(password, saltB, 32, cheapParams)
	if bytes.Equal(a, b) {
		t.Error("identical keys for different salts — salt ignored?")
	}
}

// TestDeriveKeyFromPassword_RejectsBadInputs pins the validation
// contract: empty password, short salt, zero length, zero param
// fields all return errors instead of silently using insecure
// defaults.
func TestDeriveKeyFromPassword_RejectsBadInputs(t *testing.T) {
	good := func() (pw, salt []byte, length uint32, p crypto.Argon2idParams) {
		return []byte("p"), []byte("12345678"), 32, cheapParams
	}

	cases := []struct {
		name string
		mut  func(pw, salt *[]byte, length *uint32, p *crypto.Argon2idParams)
	}{
		{"empty password", func(pw, _ *[]byte, _ *uint32, _ *crypto.Argon2idParams) { *pw = nil }},
		{"short salt", func(_, salt *[]byte, _ *uint32, _ *crypto.Argon2idParams) { *salt = []byte("short") }},
		{"zero length", func(_, _ *[]byte, l *uint32, _ *crypto.Argon2idParams) { *l = 0 }},
		{"zero time", func(_, _ *[]byte, _ *uint32, p *crypto.Argon2idParams) { p.Time = 0 }},
		{"zero memory", func(_, _ *[]byte, _ *uint32, p *crypto.Argon2idParams) { p.Memory = 0 }},
		{"zero threads", func(_, _ *[]byte, _ *uint32, p *crypto.Argon2idParams) { p.Threads = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pw, salt, length, p := good()
			tc.mut(&pw, &salt, &length, &p)
			if _, err := crypto.DeriveKeyFromPasswordWithParams(pw, salt, length, p); err == nil {
				t.Errorf("accepted bad input: %s", tc.name)
			}
		})
	}
}

// TestDefaultArgon2idParams_PassesOWASPVerifier sanity-checks the
// defaults are at or above OWASP 2024 Argon2id recommendations:
// memory >= 19 MiB (the minimum for memory-bound configs).
func TestDefaultArgon2idParams_PassesOWASPVerifier(t *testing.T) {
	p := crypto.DefaultArgon2idParams()
	const owaspMinMemoryKiB = 19 * 1024 // 19 MiB
	if p.Memory < owaspMinMemoryKiB {
		t.Errorf("DefaultArgon2idParams.Memory = %d KiB, want >= %d (OWASP 2024 minimum)",
			p.Memory, owaspMinMemoryKiB)
	}
	if p.Time < 1 {
		t.Errorf("DefaultArgon2idParams.Time = %d, want >= 1", p.Time)
	}
	if p.Threads < 1 {
		t.Errorf("DefaultArgon2idParams.Threads = %d, want >= 1", p.Threads)
	}
}

// TestDeriveKeyFromPassword_DefaultsRoundtrip exercises the convenience
// API path (no params arg) end-to-end. Slow vs cheapParams — limit to
// short keys so the 64 MiB allocation runs in <100 ms.
func TestDeriveKeyFromPassword_DefaultsRoundtrip(t *testing.T) {
	if testing.Short() {
		t.Skip("default params allocate 64 MiB — skip in -short mode")
	}
	out, err := crypto.DeriveKeyFromPassword([]byte("p"), []byte("12345678"), 16)
	if err != nil {
		t.Fatalf("DeriveKeyFromPassword: %v", err)
	}
	if len(out) != 16 {
		t.Errorf("len(out) = %d, want 16", len(out))
	}
}
