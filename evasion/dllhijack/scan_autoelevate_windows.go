//go:build windows

package dllhijack

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/oioio-space/maldev/pe/imports"
)

// ScanAutoElevate walks every .exe under %SystemRoot%\System32 that
// carries an `autoElevate=true` application manifest, analyzes its PE
// imports + DLL search order, and emits hijack Opportunities flagged
// AutoElevate + IntegrityGain.
//
// Auto-elevating binaries are Microsoft-signed processes Windows
// silently re-launches at High integrity on the current user's behalf
// without a UAC prompt (the documented "auto-approval" list). Classic
// examples: fodhelper.exe, computerdefaults.exe, sdclt.exe — the same
// binaries underpinning many UAC-bypass techniques.
//
// Corresponds to MITRE T1548.002 (Abuse Elevation Control: Bypass UAC).
//
// Requires no elevation to scan — we only read the PEs and probe
// writable directories with the current token.
func ScanAutoElevate() ([]Opportunity, error) {
	sys32 := systemDirectory()
	if sys32 == "" {
		return nil, fmt.Errorf("dllhijack/autoelevate: could not locate System32")
	}

	entries, err := os.ReadDir(sys32)
	if err != nil {
		return nil, fmt.Errorf("dllhijack/autoelevate: read System32: %w", err)
	}

	var opps []Opportunity
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.EqualFold(filepath.Ext(name), ".exe") {
			continue
		}
		full := filepath.Join(sys32, name)
		peBytes, err := os.ReadFile(full)
		if err != nil {
			continue
		}
		if !IsAutoElevate(peBytes) {
			continue
		}

		imps, err := imports.List(full)
		if err != nil {
			continue
		}
		seen := make(map[string]struct{}, len(imps))
		for _, imp := range imps {
			dllName := strings.ToLower(imp.DLL)
			if _, dup := seen[dllName]; dup {
				continue
			}
			seen[dllName] = struct{}{}

			hijackDir, resolvedDir := HijackPath(sys32, imp.DLL)
			if hijackDir == "" {
				continue
			}
			opps = append(opps, Opportunity{
				Kind:          KindAutoElevate,
				ID:            name,
				DisplayName:   name,
				BinaryPath:    full,
				HijackedDLL:   imp.DLL,
				HijackedPath:  filepath.Join(hijackDir, imp.DLL),
				ResolvedDLL:   filepath.Join(resolvedDir, imp.DLL),
				SearchDir:     hijackDir,
				Writable:      true,
				AutoElevate:   true,
				IntegrityGain: true,
				Reason:        "auto-elevate binary " + name + " imports " + imp.DLL + " resolvable from writable " + hijackDir,
			})
		}
	}
	return opps, nil
}

