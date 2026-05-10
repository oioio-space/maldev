package crypto_test

import (
	"crypto/rand"
	"testing"

	"github.com/oioio-space/maldev/crypto"
)

// Benchmarks for picking the right cipher when stub-size budget is
// tight. Run all sizes via:
//
//	go test -bench=. -benchmem -run='^$' ./crypto/
//
// or one cipher at a time via:
//
//	go test -bench=BenchmarkSpeck -benchmem -run='^$' ./crypto/
//
// Each benchmark reports ns/op, B/op, allocs/op so operators can
// compare both throughput and allocator pressure.

const benchPayload = 64 * 1024 // 64 KiB — typical stage-2 size order.

func mustRandBytes(b *testing.B, n int) []byte {
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		b.Fatalf("rand: %v", err)
	}
	return out
}

func BenchmarkAESGCM_Encrypt64K(b *testing.B) {
	key, _ := crypto.NewAESKey()
	pt := mustRandBytes(b, benchPayload)
	b.ResetTimer()
	b.SetBytes(int64(len(pt)))
	for i := 0; i < b.N; i++ {
		if _, err := crypto.EncryptAESGCM(key, pt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAESCTR_Encrypt64K(b *testing.B) {
	key := mustRandBytes(b, 32)
	pt := mustRandBytes(b, benchPayload)
	b.ResetTimer()
	b.SetBytes(int64(len(pt)))
	for i := 0; i < b.N; i++ {
		if _, err := crypto.EncryptAESCTR(key, pt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkChaCha20_Encrypt64K(b *testing.B) {
	key, _ := crypto.NewChaCha20Key()
	pt := mustRandBytes(b, benchPayload)
	b.ResetTimer()
	b.SetBytes(int64(len(pt)))
	for i := 0; i < b.N; i++ {
		if _, err := crypto.EncryptChaCha20(key, pt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkChaCha20Raw_Encrypt64K(b *testing.B) {
	key := mustRandBytes(b, 32)
	pt := mustRandBytes(b, benchPayload)
	b.ResetTimer()
	b.SetBytes(int64(len(pt)))
	for i := 0; i < b.N; i++ {
		if _, err := crypto.EncryptChaCha20Raw(key, pt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRC4_Encrypt64K(b *testing.B) {
	key := mustRandBytes(b, 32)
	pt := mustRandBytes(b, benchPayload)
	b.ResetTimer()
	b.SetBytes(int64(len(pt)))
	for i := 0; i < b.N; i++ {
		if _, err := crypto.EncryptRC4(key, pt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTEA_Encrypt64K(b *testing.B) {
	var key [16]byte
	copy(key[:], mustRandBytes(b, 16))
	pt := mustRandBytes(b, benchPayload)
	b.ResetTimer()
	b.SetBytes(int64(len(pt)))
	for i := 0; i < b.N; i++ {
		if _, err := crypto.EncryptTEA(key, pt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkXTEA_Encrypt64K(b *testing.B) {
	var key [16]byte
	copy(key[:], mustRandBytes(b, 16))
	pt := mustRandBytes(b, benchPayload)
	b.ResetTimer()
	b.SetBytes(int64(len(pt)))
	for i := 0; i < b.N; i++ {
		if _, err := crypto.EncryptXTEA(key, pt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSpeck_Encrypt64K(b *testing.B) {
	var key [16]byte
	copy(key[:], mustRandBytes(b, 16))
	pt := mustRandBytes(b, benchPayload)
	b.ResetTimer()
	b.SetBytes(int64(len(pt)))
	for i := 0; i < b.N; i++ {
		if _, err := crypto.EncryptSpeck(key, pt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkXOR_Encrypt64K(b *testing.B) {
	key := mustRandBytes(b, 32)
	pt := mustRandBytes(b, benchPayload)
	b.ResetTimer()
	b.SetBytes(int64(len(pt)))
	for i := 0; i < b.N; i++ {
		if _, err := crypto.XORWithRepeatingKey(pt, key); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHMACSHA256_64K measures the integrity-tag computation cost
// alone — relevant when picking the encrypt-then-MAC pattern over a
// single AEAD primitive.
func BenchmarkHMACSHA256_64K(b *testing.B) {
	key := mustRandBytes(b, 32)
	data := mustRandBytes(b, benchPayload)
	b.ResetTimer()
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		_ = crypto.HMACSHA256(key, data)
	}
}

// BenchmarkArgon2id_DefaultParams measures the per-call cost of the
// build-host-default Argon2id parameters (64 MiB / 1 / 4). Operators
// tuning down for CI loops compare against this baseline.
func BenchmarkArgon2id_DefaultParams(b *testing.B) {
	password := []byte("operator-passphrase")
	salt := []byte("salt-bytes-16xx")
	for i := 0; i < b.N; i++ {
		if _, err := crypto.DeriveKeyFromPassword(password, salt, 32); err != nil {
			b.Fatal(err)
		}
	}
}
