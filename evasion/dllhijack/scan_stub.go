//go:build !windows

package dllhijack

import "errors"

// ScanServices stub: the discovery scanner is Windows-only. ParseBinaryPath
// (cross-platform) lives in dllhijack.go and is usable on any OS.
func ScanServices() ([]Opportunity, error) {
	return nil, errors.New("dllhijack: ScanServices requires Windows")
}
