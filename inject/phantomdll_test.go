//go:build windows

package inject

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPhantomDLLInject_NoPID(t *testing.T) {
	err := PhantomDLLInject(0, "ntdll.dll", []byte{0xCC}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "valid target process")
}

func TestPhantomDLLInject_EmptyShellcode(t *testing.T) {
	err := PhantomDLLInject(1234, "ntdll.dll", nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestPhantomDLLInject_NegativePID(t *testing.T) {
	err := PhantomDLLInject(-1, "ntdll.dll", []byte{0xCC}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "valid target process")
}

func TestFindTextSection_InvalidPE(t *testing.T) {
	_, _, err := findTextSection([]byte{0x00, 0x00})
	assert.Error(t, err)
}

func TestFindTextSection_TooSmall(t *testing.T) {
	_, _, err := findTextSection(nil)
	assert.Error(t, err)
}
