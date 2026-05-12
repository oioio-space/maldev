//go:build !windows

package dllhijack

import (
	"errors"
	"time"
)

// ScanServices stub: the discovery scanner is Windows-only. ParseBinaryPath
// (cross-platform) lives in dllhijack.go and is usable on any OS.
func ScanServices(opts ...ScanOpts) ([]Opportunity, error) {
	return nil, errors.New("dllhijack: ScanServices requires Windows")
}

// ScanProcesses stub. Windows-only.
func ScanProcesses(opts ...ScanOpts) ([]Opportunity, error) {
	return nil, errors.New("dllhijack: ScanProcesses requires Windows")
}

// ScanScheduledTasks stub. Windows-only.
func ScanScheduledTasks(opts ...ScanOpts) ([]Opportunity, error) {
	return nil, errors.New("dllhijack: ScanScheduledTasks requires Windows")
}

// ScanAll stub. Windows-only.
func ScanAll(opts ...ScanOpts) ([]Opportunity, error) {
	return nil, errors.New("dllhijack: ScanAll requires Windows")
}

// SearchOrder stub. Windows-only.
func SearchOrder(exeDir string) []string { return nil }

// HijackPath stub. Windows-only; always returns empty strings.
func HijackPath(exeDir, dllName string) (string, string) { return "", "" }

// ValidationResult is a cross-platform type so callers can reference it
// from non-Windows code paths; the Windows definition is authoritative.
type ValidationResult struct {
	Dropped, Triggered, Confirmed, CleanedUp bool
	MarkerPath                               string
	MarkerContents                           []byte
	Errors                                   []string
}

// ValidateOpts is a cross-platform type; see validate_windows.go for the
// field meanings.
type ValidateOpts struct {
	MarkerGlob   string
	MarkerDir    string
	Timeout      time.Duration
	PollInterval time.Duration
	KeepCanary   bool
}

// Validate stub. Windows-only.
func Validate(opp Opportunity, canaryDLL []byte, opts ValidateOpts) (*ValidationResult, error) {
	return nil, errors.New("dllhijack: Validate requires Windows")
}

// ScanAutoElevate stub. Windows-only.
func ScanAutoElevate(opts ...ScanOpts) ([]Opportunity, error) {
	return nil, errors.New("dllhijack: ScanAutoElevate requires Windows")
}

// ScanPATHWritable stub. Windows-only.
func ScanPATHWritable(opts ...ScanOpts) ([]Opportunity, error) {
	return nil, errors.New("dllhijack: ScanPATHWritable requires Windows")
}
