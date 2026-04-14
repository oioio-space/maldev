//go:build windows

package herpaderping

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/oioio-space/maldev/testutil"
)

func TestConfigValidation(t *testing.T) {
	// Empty config should not panic
	cfg := Config{}
	assert.Empty(t, cfg.PayloadPath)
	assert.Empty(t, cfg.TargetPath)
	assert.Empty(t, cfg.DecoyPath)
}

func TestRunMissingPayload(t *testing.T) {
	err := Run(Config{PayloadPath: "/nonexistent/payload.exe"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "read payload")
}

func TestRunInvalidPE(t *testing.T) {
	testutil.RequireIntrusive(t)
	// Write random bytes (not a valid PE) to a temp file
	dir := t.TempDir()
	payloadPath := filepath.Join(dir, "notape.exe")
	os.WriteFile(payloadPath, []byte{0xDE, 0xAD, 0xBE, 0xEF}, 0644)

	targetPath := filepath.Join(dir, "target.exe")
	err := Run(Config{
		PayloadPath: payloadPath,
		TargetPath:  targetPath,
	})
	// NtCreateSection with SEC_IMAGE should fail on invalid PE
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "NtCreateSection")
}

// TestRunWithDecoy performs a full herpaderping execution using cmd.exe /c echo
// as the payload and svchost.exe as the decoy.
//
// PREREQUISITES:
//   - Run in a VM with administrator privileges
//   - Windows 10 or later
//
// USAGE:
//
//	MALDEV_MANUAL=1 MALDEV_INTRUSIVE=1 go test ./evasion/herpaderping/ -run TestRunWithDecoy -v -timeout 30s
//
// VERIFY:
//
//	The test creates a process from a copy of cmd.exe, overwrites the disk
//	file with svchost.exe, then lets the process run. Check Task Manager
//	for a process whose image path shows the target file but actual behavior
//	matches cmd.exe.
//
// CLEANUP:
//
//	The target file is cleaned up automatically by t.TempDir().
func TestRunWithDecoy(t *testing.T) {
	testutil.RequireManual(t)
	testutil.RequireIntrusive(t)

	dir := t.TempDir()
	// Use cmd.exe as a benign "payload" that exits quickly
	payloadPath := `C:\Windows\System32\cmd.exe`
	targetPath := filepath.Join(dir, "herp.exe")
	decoyPath := `C:\Windows\System32\svchost.exe`

	err := Run(Config{
		PayloadPath: payloadPath,
		TargetPath:  targetPath,
		DecoyPath:   decoyPath,
	})
	require.NoError(t, err)

	// Verify the file on disk is now svchost.exe, not cmd.exe
	diskContent, err := os.ReadFile(targetPath)
	if err == nil {
		// If file still exists, it should match decoy not payload
		origPayload, _ := os.ReadFile(payloadPath)
		origDecoy, _ := os.ReadFile(decoyPath)
		assert.NotEqual(t, origPayload[:100], diskContent[:100], "disk should not match payload")
		assert.Equal(t, origDecoy[:100], diskContent[:100], "disk should match decoy")
	}
	t.Log("herpaderping completed successfully — process created with decoy on disk")
}

// TestRunWithMarkerPayload uses the marker_x64.bin shellcode payload wrapped
// in a PE to prove herpaderping actually EXECUTES the payload, not just creates
// a process. The marker shellcode writes C:\maldev_test_marker.txt.
//
// Note: marker_x64.bin is raw shellcode, not a PE. Herpaderping requires a PE
// as payload (NtCreateSection SEC_IMAGE). So we use cmd.exe as the payload PE
// and verify the process was created by checking it ran (not the marker).
// True payload execution verification requires a custom PE that produces
// a measurable side effect — a future enhancement.
func TestRunVerifyProcessCreated(t *testing.T) {
	testutil.RequireManual(t)
	testutil.RequireIntrusive(t)

	dir := t.TempDir()
	payloadPath := `C:\Windows\System32\cmd.exe`
	targetPath := filepath.Join(dir, "herp_verify.exe")

	err := Run(Config{
		PayloadPath: payloadPath,
		TargetPath:  targetPath,
	})
	require.NoError(t, err)

	// The process was created from cmd.exe via herpaderping.
	// Verify the target file was overwritten with random bytes (no decoy = random).
	diskContent, readErr := os.ReadFile(targetPath)
	if readErr == nil {
		origPayload, _ := os.ReadFile(payloadPath)
		assert.NotEqual(t, origPayload[:64], diskContent[:64],
			"disk content should differ from original payload (overwritten with decoy/random)")
		t.Logf("target file size: %d (original cmd.exe: %d)", len(diskContent), len(origPayload))
	}
}

func TestTechniqueInterface(t *testing.T) {
	tech := Technique(Config{PayloadPath: "test.exe"})
	assert.Equal(t, "herpaderping", tech.Name())
}
