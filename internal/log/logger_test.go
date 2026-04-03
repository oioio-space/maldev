//go:build !debug

package log

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNop(t *testing.T) {
	l := Nop()
	assert.NotNil(t, l, "Nop() must return a non-nil Logger")
}

func TestNopMethods(t *testing.T) {
	l := Nop()
	// None of these should panic.
	l.Info("msg", "key", "val")
	l.Warn("msg", "key", "val")
	l.Error("msg", "key", "val")
	l.Debug("msg", "key", "val")
}

func TestNew(t *testing.T) {
	l := New(nil)
	assert.NotNil(t, l, "New(nil) must return a non-nil Logger")
}

func TestEnabled(t *testing.T) {
	l := Nop()
	assert.False(t, l.Enabled(), "Enabled() must return false in release build")
}
