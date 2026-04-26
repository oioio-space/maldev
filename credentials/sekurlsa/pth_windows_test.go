//go:build windows

package sekurlsa

import (
	"bytes"
	"errors"
	"testing"
)

// validPTHParams is the minimal happy-path Params used as a base for
// the rejection tests below — each test mutates exactly one field
// to the bad shape it asserts against.
func validPTHParams() PTHParams {
	return PTHParams{
		Target: PTHTarget{
			Domain:   "corp.example.com",
			Username: "Administrator",
			NTLM:     bytes.Repeat([]byte{0xAA}, 16),
		},
	}
}

func TestPass_RejectsMissingDomain(t *testing.T) {
	p := validPTHParams()
	p.Target.Domain = ""
	_, err := Pass(p)
	if !errors.Is(err, ErrPTHInvalidTarget) {
		t.Fatalf("Pass: err = %v, want wrap of ErrPTHInvalidTarget", err)
	}
}

func TestPass_RejectsMissingUsername(t *testing.T) {
	p := validPTHParams()
	p.Target.Username = ""
	_, err := Pass(p)
	if !errors.Is(err, ErrPTHInvalidTarget) {
		t.Fatalf("Pass: err = %v, want wrap of ErrPTHInvalidTarget", err)
	}
}

func TestPass_RejectsBadNTLMLength(t *testing.T) {
	cases := [][]byte{
		nil,
		bytes.Repeat([]byte{1}, 8),  // too short
		bytes.Repeat([]byte{1}, 32), // too long
	}
	for _, ntlm := range cases {
		p := validPTHParams()
		p.Target.NTLM = ntlm
		_, err := Pass(p)
		if !errors.Is(err, ErrPTHInvalidTarget) {
			t.Errorf("NTLM len=%d: err = %v, want wrap of ErrPTHInvalidTarget", len(ntlm), err)
		}
	}
}

func TestPass_RejectsBadAES128Length(t *testing.T) {
	p := validPTHParams()
	p.Target.AES128 = bytes.Repeat([]byte{1}, 17) // not empty, not 16
	_, err := Pass(p)
	if !errors.Is(err, ErrPTHInvalidTarget) {
		t.Fatalf("Pass: err = %v, want wrap of ErrPTHInvalidTarget", err)
	}
}

func TestPass_RejectsBadAES256Length(t *testing.T) {
	p := validPTHParams()
	p.Target.AES256 = bytes.Repeat([]byte{1}, 31) // not empty, not 32
	_, err := Pass(p)
	if !errors.Is(err, ErrPTHInvalidTarget) {
		t.Fatalf("Pass: err = %v, want wrap of ErrPTHInvalidTarget", err)
	}
}

// TestPass_StubReturnsNotImplemented documents the chantier-II-in-
// progress contract: with valid Params, Pass currently returns the
// ErrPTHNotImplemented sentinel. This test will flip to assert real
// Result fields once the implementation lands; until then it pins
// the placeholder behavior so callers depending on the public API
// shape know what to expect.
func TestPass_StubReturnsNotImplemented(t *testing.T) {
	_, err := Pass(validPTHParams())
	if !errors.Is(err, ErrPTHNotImplemented) {
		t.Fatalf("Pass with valid params: err = %v, want ErrPTHNotImplemented", err)
	}
}

func TestPassImpersonate_RejectsMissingDomain(t *testing.T) {
	p := validPTHParams()
	p.Target.Domain = ""
	_, err := PassImpersonate(p)
	if !errors.Is(err, ErrPTHInvalidTarget) {
		t.Fatalf("PassImpersonate: err = %v, want wrap of ErrPTHInvalidTarget", err)
	}
}

func TestPassImpersonate_StubReturnsNotImplemented(t *testing.T) {
	_, err := PassImpersonate(validPTHParams())
	if !errors.Is(err, ErrPTHNotImplemented) {
		t.Fatalf("PassImpersonate: err = %v, want ErrPTHNotImplemented", err)
	}
}

// TestPTHSentinels_AreDistinct guards against accidental aliasing
// when adding new sentinels — each errors.Is check above relies on
// the wrapped error being uniquely identifiable.
func TestPTHSentinels_AreDistinct(t *testing.T) {
	all := []error{
		ErrPTHInvalidTarget,
		ErrPTHSpawnFailed,
		ErrPTHWriteFailed,
		ErrPTHNoMatchingLUID,
		ErrPTHNotImplemented,
	}
	for i, a := range all {
		for j, b := range all {
			if i != j && errors.Is(a, b) {
				t.Errorf("sentinel %v unexpectedly Is %v", a, b)
			}
		}
	}
}
