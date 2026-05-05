package goldenticket

import (
	"bytes"
	"errors"
	"testing"

	"github.com/oioio-space/maldev/internal/msrpc/msrpc/pac"
)

// tamperSignatureByte flips a byte inside the signature payload of the
// requested PAC info-buffer type (0x06 = server, 0x07 = KDC). Uses the
// PAC's own Buffers metadata so the test doesn't depend on
// buildPAC's emission order, which would otherwise drift silently
// when new buffer types are added.
func tamperSignatureByte(t *testing.T, pacBytes []byte, bufType uint32) []byte {
	t.Helper()
	var p pac.PAC
	if err := p.Unmarshal(pacBytes); err != nil {
		t.Fatalf("Unmarshal for tamper: %v", err)
	}
	for _, b := range p.Buffers {
		if b.Type != bufType {
			continue
		}
		out := append([]byte(nil), pacBytes...)
		// Signature payload starts 4 bytes past the buffer offset
		// (skip the SignatureType uint32 prefix). Flip the first
		// payload byte — any byte inside the payload would do.
		out[b.Offset+4] ^= 0xFF
		return out
	}
	t.Fatalf("PAC buffer type 0x%X not found", bufType)
	return nil
}

// pacForOk produces a valid PAC byte stream for the okParams() test
// fixture — rebuilt fresh per test so corruption assertions can mutate
// without affecting siblings.
func pacForOk(t *testing.T) ([]byte, Hash) {
	t.Helper()
	p := okParams()
	np, err := p.normalize()
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	pacBytes, err := buildPAC(np)
	if err != nil {
		t.Fatalf("buildPAC: %v", err)
	}
	return pacBytes, p.Hash
}

func TestValidatePAC_RejectsEmptyBytes(t *testing.T) {
	if err := ValidatePAC(nil, fixedHash()); err == nil {
		t.Fatal("ValidatePAC(nil) returned nil, want error")
	}
	if err := ValidatePAC([]byte{}, fixedHash()); err == nil {
		t.Fatal("ValidatePAC([]byte{}) returned nil, want error")
	}
}

func TestValidatePAC_RejectsBogusBytes(t *testing.T) {
	bogus := bytes.Repeat([]byte{0xAA}, 256)
	if err := ValidatePAC(bogus, fixedHash()); err == nil {
		t.Fatal("ValidatePAC(bogus) returned nil, want error")
	}
}

func TestValidatePAC_RoundTripRC4(t *testing.T) {
	pacBytes, h := pacForOk(t)
	if err := ValidatePAC(pacBytes, h); err != nil {
		t.Fatalf("ValidatePAC(forged RC4): %v", err)
	}
}

func TestValidatePAC_RoundTripAES256(t *testing.T) {
	p := okParams()
	p.Hash = Hash{Type: ETypeAES256CTS, Bytes: bytes.Repeat([]byte{0x42}, 32)}
	np, err := p.normalize()
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	pacBytes, err := buildPAC(np)
	if err != nil {
		t.Fatalf("buildPAC: %v", err)
	}
	if err := ValidatePAC(pacBytes, p.Hash); err != nil {
		t.Fatalf("ValidatePAC(forged AES256): %v", err)
	}
}

func TestValidatePAC_RoundTripAES128(t *testing.T) {
	p := okParams()
	p.Hash = Hash{Type: ETypeAES128CTS, Bytes: bytes.Repeat([]byte{0x33}, 16)}
	np, err := p.normalize()
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	pacBytes, err := buildPAC(np)
	if err != nil {
		t.Fatalf("buildPAC: %v", err)
	}
	if err := ValidatePAC(pacBytes, p.Hash); err != nil {
		t.Fatalf("ValidatePAC(forged AES128): %v", err)
	}
}

func TestValidatePAC_DetectsServerSignatureTampering(t *testing.T) {
	pacBytes, h := pacForOk(t)
	corrupted := tamperSignatureByte(t, pacBytes, pacInfoBufferTypeServerChecksum)
	err := ValidatePAC(corrupted, h)
	if !errors.Is(err, ErrInvalidServerSignature) {
		t.Fatalf("ValidatePAC(server sig tampered) = %v, want %v",
			err, ErrInvalidServerSignature)
	}
}

func TestValidatePAC_DetectsKDCSignatureTampering(t *testing.T) {
	pacBytes, h := pacForOk(t)
	corrupted := tamperSignatureByte(t, pacBytes, pacInfoBufferTypeKDCChecksum)
	err := ValidatePAC(corrupted, h)
	if !errors.Is(err, ErrInvalidKDCSignature) {
		t.Fatalf("ValidatePAC(KDC sig tampered) = %v, want %v",
			err, ErrInvalidKDCSignature)
	}
}

func TestValidatePAC_DetectsWrongKey(t *testing.T) {
	pacBytes, _ := pacForOk(t)

	wrong := Hash{Type: ETypeRC4HMAC, Bytes: bytes.Repeat([]byte{0xDE}, 16)}
	err := ValidatePAC(pacBytes, wrong)
	if !errors.Is(err, ErrInvalidServerSignature) {
		t.Fatalf("ValidatePAC(wrong key) = %v, want %v", err, ErrInvalidServerSignature)
	}
}

func TestValidatePAC_DetectsWrongEType(t *testing.T) {
	pacBytes, h := pacForOk(t) // RC4
	wrongType := Hash{Type: ETypeAES256CTS, Bytes: bytes.Repeat([]byte{0x42}, 32)}
	_ = h
	err := ValidatePAC(pacBytes, wrongType)
	// AES checksum applied to RC4-emitted PAC bytes → either an
	// internal compute error (wrong key length) or a signature
	// mismatch. Either way the result is non-nil.
	if err == nil {
		t.Fatal("ValidatePAC(wrong etype) returned nil, want error")
	}
}
