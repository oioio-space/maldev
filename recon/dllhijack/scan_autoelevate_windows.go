//go:build windows

package dllhijack

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/oioio-space/maldev/evasion/stealthopen"
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
func ScanAutoElevate(opts ...ScanOpts) ([]Opportunity, error) {
	o := firstOpts(opts)
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
		peBytes, err := stealthopen.OpenRead(o.Opener, full)
		if err != nil {
			continue
		}
		if !IsAutoElevate(peBytes) {
			continue
		}

		imps, err := importsFromBytes(peBytes)
		if err != nil {
			continue
		}
		dllNames := make([]string, 0, len(imps))
		for _, imp := range imps {
			dllNames = append(dllNames, imp.DLL)
		}
		binName := name
		opps = append(opps, emitOppsForDLLs(
			full, sys32, KindAutoElevate, name, name, dllNames,
			func(dll, hijackDir, _ string) string {
				return "auto-elevate binary " + binName + " imports " + dll + " resolvable from writable " + hijackDir
			},
			func(o *Opportunity) {
				o.AutoElevate = true
				o.IntegrityGain = true
			},
		)...)
	}
	return opps, nil
}

