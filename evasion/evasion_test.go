package evasion

import "testing"

type mockTechnique struct{}

func (mockTechnique) Name() string          { return "mock" }
func (mockTechnique) Apply(_ Caller) error  { return nil }

func TestApplyAll_Empty(t *testing.T) {
	errs := ApplyAll(nil, nil)
	if errs != nil {
		t.Fatal("expected nil for empty slice")
	}
}

func TestApplyAll_NilCaller(t *testing.T) {
	errs := ApplyAll([]Technique{mockTechnique{}}, nil)
	if errs != nil {
		t.Fatalf("expected nil, got %v", errs)
	}
}
