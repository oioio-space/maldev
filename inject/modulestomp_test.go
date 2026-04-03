//go:build windows

package inject

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/oioio-space/maldev/testutil"
)

func TestModuleStomp(t *testing.T) {
	testutil.RequireWindows(t)
	testutil.RequireIntrusive(t)

	addr, err := ModuleStomp("msftedit.dll", testutil.WindowsCanaryX64)
	require.NoError(t, err)
	assert.NotZero(t, addr)
}

func TestModuleStomp_TooLarge(t *testing.T) {
	testutil.RequireWindows(t)
	testutil.RequireIntrusive(t)

	// 100 MB shellcode exceeds any .text section.
	huge := make([]byte, 100*1024*1024)
	_, err := ModuleStomp("msftedit.dll", huge)
	assert.Error(t, err)
}

func TestModuleStomp_EmptyShellcode(t *testing.T) {
	_, err := ModuleStomp("msftedit.dll", nil)
	assert.Error(t, err)
}
