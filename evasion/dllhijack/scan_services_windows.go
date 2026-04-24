//go:build windows

package dllhijack

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/oioio-space/maldev/pe/imports"
)

// ScanServices enumerates every installed Windows service, parses its
// binary's import table, and emits one Opportunity per (service,
// importedDLL) pair where Windows' DLL search order exposes a
// user-writable directory earlier than the DLL's real location.
//
// This is the "real" filter: we no longer flag every writable service
// dir, only the ones where a specific DLL can be hijacked. Services
// whose binary cannot be opened, whose imports cannot be parsed, or
// whose Config cannot be read are silently skipped.
//
// Requires no elevation.
func ScanServices() ([]Opportunity, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, fmt.Errorf("dllhijack/services: connect to SCM: %w", err)
	}
	defer m.Disconnect()

	names, err := m.ListServices()
	if err != nil {
		return nil, fmt.Errorf("dllhijack/services: list services: %w", err)
	}

	var opps []Opportunity
	for _, name := range names {
		s, err := m.OpenService(name)
		if err != nil {
			continue
		}
		cfg, err := s.Config()
		s.Close()
		if err != nil {
			continue
		}

		binPath := ParseBinaryPath(cfg.BinaryPathName)
		if binPath == "" {
			continue
		}
		binPath = expandEnvVars(binPath)
		if !fileExists(binPath) {
			continue
		}
		exeDir := filepath.Dir(binPath)

		imps, err := imports.List(binPath)
		if err != nil {
			continue
		}

		// Dedup DLL names — a single DLL may export many imported
		// functions; we only care about the DLL name.
		seen := make(map[string]struct{}, len(imps))
		for _, imp := range imps {
			dllName := strings.ToLower(imp.DLL)
			if _, dup := seen[dllName]; dup {
				continue
			}
			seen[dllName] = struct{}{}

			hijackDir, resolvedDir := HijackPath(exeDir, imp.DLL)
			if hijackDir == "" {
				continue
			}
			opps = append(opps, Opportunity{
				Kind:         KindService,
				ID:           name,
				DisplayName:  cfg.DisplayName,
				BinaryPath:   binPath,
				HijackedDLL:  imp.DLL,
				HijackedPath: filepath.Join(hijackDir, imp.DLL),
				ResolvedDLL:  filepath.Join(resolvedDir, imp.DLL),
				SearchDir:    hijackDir,
				Writable:     true,
				Reason:       "import " + imp.DLL + " resolves from writable " + hijackDir + " before " + resolvedDir,
			})
		}
	}
	return opps, nil
}

// expandEnvVars expands %SystemRoot%-style placeholders that the SCM
// sometimes stores in BinaryPathName. Falls back to the original
// string on error.
func expandEnvVars(p string) string {
	in, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return p
	}
	out := make([]uint16, windows.MAX_PATH*2)
	n, err := windows.ExpandEnvironmentStrings(in, &out[0], uint32(len(out)))
	if err != nil || n == 0 {
		return p
	}
	return windows.UTF16ToString(out[:n])
}

// dirWritable returns true if the current process can create a file in
// dir. Uses O_EXCL so we never overwrite an existing file; probe is
// removed on success.
func dirWritable(dir string) bool {
	probe := filepath.Join(dir, ".maldev-dllhijack-probe")
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o644)
	if err != nil {
		return false
	}
	f.Close()
	os.Remove(probe)
	return true
}
