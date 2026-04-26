//go:build !windows

package lsassdump

import "fmt"

// defaultNtoskrnlPath on non-Windows platforms cannot auto-resolve
// the kernel image — there's no `%SystemRoot%`. Callers running on
// Linux/CI MUST pass an explicit path to a captured ntoskrnl.exe.
// `caller` names the public entry point so the error message points
// at the right export.
func defaultNtoskrnlPath(path, caller string) (string, error) {
	if path != "" {
		return path, nil
	}
	return "", fmt.Errorf("%s: empty path on non-Windows; pass a captured ntoskrnl.exe explicitly", caller)
}
