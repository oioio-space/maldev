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
