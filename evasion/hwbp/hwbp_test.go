//go:build windows

package hwbp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetect(t *testing.T) {
	// In a normal test environment, no hardware breakpoints should be set.
	bps, err := Detect()
	require.NoError(t, err)
	// May be empty (no EDR) or non-empty (EDR present) — just verify no panic.
	t.Logf("current thread breakpoints: %d", len(bps))
}

func TestDetectAll(t *testing.T) {
	bps, err := DetectAll()
	require.NoError(t, err)
	t.Logf("all threads breakpoints: %d", len(bps))
	for _, bp := range bps {
		t.Logf("  DR%d = 0x%X (thread %d)", bp.Register, bp.Address, bp.ThreadID)
	}
}

func TestClearAll(t *testing.T) {
	cleared, err := ClearAll()
	require.NoError(t, err)
	assert.Greater(t, cleared, 0, "should modify at least one thread (current)")

	// After clearing, Detect should find nothing.
	bps, err := Detect()
	require.NoError(t, err)
	assert.Empty(t, bps, "no breakpoints should remain after ClearAll")
}
