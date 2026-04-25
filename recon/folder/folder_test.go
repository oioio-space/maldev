//go:build windows

package folder

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetFolder(t *testing.T) {
	// CSIDL_WINDOWS (0x24) should always resolve to the Windows directory.
	path := Get(CSIDL_WINDOWS, false)
	assert.NotEmpty(t, path, "CSIDL_WINDOWS should return a non-empty path")
	assert.True(t, strings.Contains(strings.ToLower(path), "windows"),
		"expected path to contain 'windows', got: %s", path)
}

func TestGetFolderSystem(t *testing.T) {
	// CSIDL_SYSTEM (0x25) should resolve to the System32 directory.
	path := Get(CSIDL_SYSTEM, false)
	assert.NotEmpty(t, path, "CSIDL_SYSTEM should return a non-empty path")
	assert.True(t, strings.Contains(strings.ToLower(path), "system32"),
		"expected path to contain 'system32', got: %s", path)
}

func TestGetFolderProgramFiles(t *testing.T) {
	// CSIDL_PROGRAM_FILES (0x26) should return a non-empty path.
	path := Get(CSIDL_PROGRAM_FILES, false)
	assert.NotEmpty(t, path, "CSIDL_PROGRAM_FILES should return a non-empty path")
}

func TestGetFolderAppData(t *testing.T) {
	path := Get(CSIDL_APPDATA, false)
	assert.NotEmpty(t, path, "CSIDL_APPDATA should return a non-empty path")
	assert.True(t, strings.Contains(strings.ToLower(path), "appdata"),
		"expected path to contain 'appdata', got: %s", path)
}

func TestGetFolderStartup(t *testing.T) {
	path := Get(CSIDL_STARTUP, false)
	assert.NotEmpty(t, path, "CSIDL_STARTUP should return a non-empty path")
}

func TestGetFolderInvalidCSIDL(t *testing.T) {
	path := Get(CSIDL(0xFF), false)
	assert.Empty(t, path)
}
