//go:build windows

package inject

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKernelCallbackExec_NoPID(t *testing.T) {
	err := KernelCallbackExec(0, []byte{0xCC}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "valid target process")
}

func TestKernelCallbackExec_NegativePID(t *testing.T) {
	err := KernelCallbackExec(-1, []byte{0xCC}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "valid target process")
}

func TestKernelCallbackExec_EmptyShellcode(t *testing.T) {
	err := KernelCallbackExec(1234, nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}
