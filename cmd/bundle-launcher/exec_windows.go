//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// executePayload writes payload to a temp file in TMP and runs it via
// CreateProcess. Inherits stdio so the child's output reaches the
// caller's terminal.
//
// Windows has no clean memfd-equivalent that integrates with the PE
// loader for in-memory execution from a non-elevated process, so we
// drop to a temp file. The file is created with 0o700 (Windows ACLs
// inherit the user's profile permissions; this exe is owner-only by
// default on NTFS) and removed after the child exits or this process
// terminates.
func executePayload(payload []byte, args []string) error {
	tmp, err := os.CreateTemp("", "bundle-payload-*.exe")
	if err != nil {
		return fmt.Errorf("CreateTemp: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(payload); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("temp write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("temp close: %w", err)
	}
	defer os.Remove(tmpPath)

	cmd := exec.Command(filepath.Clean(tmpPath), args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
