//go:build windows

package service

import (
	"errors"
	"fmt"
	"math/rand"
	"os/exec"
	"syscall"
	"testing"
)

func isAdmin() bool {
	cmd := exec.Command("net", "session")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run() == nil
}

func TestExists(t *testing.T) {
	// SCM read access may require elevation on some configurations.
	if !Exists("Winmgmt") {
		if !isAdmin() {
			t.Skip("SCM access denied without elevation")
		}
		t.Fatal("Exists returned false for Winmgmt service")
	}
}

func TestExistsNonExistent(t *testing.T) {
	name := "maldev_test_" + fmt.Sprintf("%x", rand.Int63())
	// Non-existent service: Exists returns false regardless of privileges.
	if Exists(name) {
		t.Fatalf("Exists returned true for non-existent service")
	}
}

func TestIsRunning(t *testing.T) {
	if !isAdmin() {
		t.Skip("SCM query access may require elevation")
	}
	if !IsRunning("Winmgmt") {
		t.Fatal("IsRunning returned false for Winmgmt service")
	}
}

func TestInstallAccessDenied(t *testing.T) {
	if isAdmin() {
		t.Skip("test requires non-elevated process")
	}

	cfg := &Config{
		Name:        "maldev_test_" + fmt.Sprintf("%x", rand.Int63()),
		DisplayName: "maldev test service",
		BinPath:     `C:\Windows\System32\cmd.exe`,
		StartType:   StartManual,
	}

	err := Install(cfg)
	if err == nil {
		t.Fatal("Install should fail without elevation")
	}
	if !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("expected ErrAccessDenied, got: %v", err)
	}
}
