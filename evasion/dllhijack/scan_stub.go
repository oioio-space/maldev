//go:build !windows

package dllhijack

import "errors"

// ScanServices stub: the discovery scanner is Windows-only. ParseBinaryPath
// (cross-platform) lives in dllhijack.go and is usable on any OS.
func ScanServices() ([]Opportunity, error) {
	return nil, errors.New("dllhijack: ScanServices requires Windows")
}

// SearchOrder stub. Windows-only.
func SearchOrder(exeDir string) []string { return nil }

// HijackPath stub. Windows-only; always returns empty strings.
func HijackPath(exeDir, dllName string) (string, string) { return "", "" }
