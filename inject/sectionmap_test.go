//go:build windows

package inject

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSectionMapInject_EmptyShellcode(t *testing.T) {
	err := SectionMapInject(1234, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestSectionMapInject_NoPID(t *testing.T) {
	err := SectionMapInject(0, []byte{0x90, 0xCC}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}
