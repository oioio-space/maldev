//go:build windows

package dllhijack

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/svc/mgr"
)

// ScanServices enumerates every installed Windows service and returns
// an Opportunity for those whose binary directory is writable by the
// current user — a classic DLL-hijack vector: drop a DLL named like
// one of the service binary's imports and the service loads it on
// next start.
//
// Requires no elevation to enumerate; the writability probe runs as
// the current token. Services whose Config cannot be read (access
// denied, missing registry keys) are silently skipped.
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
		dir := filepath.Dir(binPath)
		if dir == "" || dir == "." {
			continue
		}

		if !dirWritable(dir) {
			continue
		}

		opps = append(opps, Opportunity{
			Kind:        KindService,
			ID:          name,
			DisplayName: cfg.DisplayName,
			BinaryPath:  binPath,
			SearchDir:   dir,
			Writable:    true,
			Reason:      "service binary directory writable by current user",
		})
	}
	return opps, nil
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
