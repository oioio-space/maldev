package antivm

import (
	"testing"
)

func TestDetectVMNoPanic(t *testing.T) {
	// DetectVM inspects host indicators; it must not panic regardless of result.
	_ = DetectVM()
}

func TestIsRunningInVMNoPanic(t *testing.T) {
	// IsRunningInVM wraps DetectVM; it must not panic regardless of result.
	_ = IsRunningInVM()
}
