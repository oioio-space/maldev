//go:build windows

package ads

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// CreateUndeletable creates a file with a name that Windows Explorer and cmd
// cannot delete (trailing dots trick). Only \\?\ prefix or NtCreateFile can access it.
// Returns the full path to the created file.
func CreateUndeletable(dir string, data []byte) (string, error) {
	// The "..." trick: filenames ending with dots are stripped by Win32 API
	// but NtCreateFile (via \\?\ prefix) preserves them.
	name := "..."
	fullPath := dir + `\` + name

	// Use \\?\ prefix to bypass Win32 name normalization.
	ntPath := `\\?\` + fullPath

	pathPtr, err := windows.UTF16PtrFromString(ntPath)
	if err != nil {
		return "", fmt.Errorf("invalid path: %w", err)
	}

	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_WRITE,
		0,
		nil,
		windows.CREATE_ALWAYS,
		windows.FILE_ATTRIBUTE_HIDDEN|windows.FILE_ATTRIBUTE_SYSTEM,
		0,
	)
	if err != nil {
		return "", fmt.Errorf("CreateFile: %w", err)
	}
	defer windows.CloseHandle(handle) //nolint:errcheck

	if len(data) > 0 {
		var written uint32
		if err = windows.WriteFile(handle, data, &written, nil); err != nil {
			return "", fmt.Errorf("WriteFile: %w", err)
		}
	}

	return fullPath, nil
}

// ReadUndeletable reads a file created by CreateUndeletable.
func ReadUndeletable(path string) ([]byte, error) {
	ntPath := `\\?\` + path
	return os.ReadFile(ntPath)
}
