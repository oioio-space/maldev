//go:build windows

package cve202430088

import (
	"fmt"

	winver "github.com/oioio-space/maldev/win/version"
)

// VersionInfo contains Windows version details and vulnerability status.
type VersionInfo struct {
	Major      uint32
	Minor      uint32
	Build      uint32
	Revision   uint32
	Vulnerable bool
	Edition    string
}

// CheckVersion queries the running Windows version and checks if it is
// vulnerable to CVE-2024-30088. Delegates to win/version.CVE202430088().
func CheckVersion() (VersionInfo, error) {
	wv, err := winver.CVE202430088()
	if err != nil {
		return VersionInfo{}, fmt.Errorf("getting Windows version: %w", err)
	}
	return VersionInfo{
		Major:      wv.Major,
		Minor:      wv.Minor,
		Build:      wv.Build,
		Revision:   wv.Revision,
		Vulnerable: wv.Vulnerable,
		Edition:    wv.Edition,
	}, nil
}
