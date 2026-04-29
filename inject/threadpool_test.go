//go:build windows

package inject

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestThreadPoolExec_EmptyShellcode(t *testing.T) {
	err := ThreadPoolExec(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestThreadPoolExec_ZeroLenShellcode(t *testing.T) {
	err := ThreadPoolExec([]byte{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

// TestThreadPoolExecCET_EmptyShellcode confirms the CET-aware wrapper
// inherits ThreadPoolExec's input validation. Wrap is a no-op on
// non-enforced hosts so the empty input path always reaches the
// underlying validateShellcode call regardless of CET state.
func TestThreadPoolExecCET_EmptyShellcode(t *testing.T) {
	err := ThreadPoolExecCET(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestThreadPoolExecCET_ZeroLenShellcode(t *testing.T) {
	err := ThreadPoolExecCET([]byte{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}
