package evasion_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/oioio-space/maldev/evasion"
)

// stubTechnique is a deterministic [evasion.Technique] for tests.
type stubTechnique struct {
	name string
	err  error
}

func (s stubTechnique) Name() string                  { return s.name }
func (s stubTechnique) Apply(_ evasion.Caller) error  { return s.err }

func TestApplyAllAggregated_NilOnSuccess(t *testing.T) {
	techs := []evasion.Technique{
		stubTechnique{name: "amsi", err: nil},
		stubTechnique{name: "etw", err: nil},
	}
	if err := evasion.ApplyAllAggregated(techs, nil); err != nil {
		t.Fatalf("ApplyAllAggregated = %v, want nil when every technique OK", err)
	}
}

func TestApplyAllAggregated_AllNamesOnFailure(t *testing.T) {
	techs := []evasion.Technique{
		stubTechnique{name: "etw", err: errors.New("etw boom")},
		stubTechnique{name: "amsi", err: errors.New("amsi boom")},
		stubTechnique{name: "unhook", err: nil}, // succeeds — must not appear
	}
	err := evasion.ApplyAllAggregated(techs, nil)
	if err == nil {
		t.Fatal("ApplyAllAggregated = nil, want non-nil with 2 failing techniques")
	}
	msg := err.Error()
	// Single error must mention every failing technique by name.
	for _, want := range []string{"amsi", "etw", "amsi boom", "etw boom"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q missing substring %q", msg, want)
		}
	}
	// Alphabetic order: "amsi" must appear before "etw" in the message.
	if strings.Index(msg, "amsi") > strings.Index(msg, "etw") {
		t.Errorf("failures not sorted alphabetically: %q", msg)
	}
	// Successful technique must NOT appear in the aggregated message.
	if strings.Contains(msg, "unhook") {
		t.Errorf("error %q leaks succeeding technique 'unhook'", msg)
	}
	// Counter shape "N/M techniques failed" must reflect both counts.
	if !strings.Contains(msg, "2/3 techniques failed") {
		t.Errorf("error %q missing '2/3 techniques failed' counter", msg)
	}
}
