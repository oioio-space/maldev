//go:build windows

package service

import (
	"errors"
	"fmt"
	"math/rand"
	"testing"

	"github.com/oioio-space/maldev/persistence/account"
)

func TestExists(t *testing.T) {
	// SCM read access may require elevation on some configurations.
	if !Exists("Winmgmt") {
		if !user.IsAdmin() {
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
	if !user.IsAdmin() {
		t.Skip("SCM query access may require elevation")
	}
	if !IsRunning("Winmgmt") {
		t.Fatal("IsRunning returned false for Winmgmt service")
	}
}

func TestInstallAccessDenied(t *testing.T) {
	if user.IsAdmin() {
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

// TestConfig_AccountFieldsTypeCheck pins the new Account / Password
// fields exist and type-check. SCM-side behaviour is host-dependent
// (need a real account + SeServiceLogonRight) so the install path
// itself stays in the VM matrix.
func TestConfig_AccountFieldsTypeCheck(t *testing.T) {
	cfg := &Config{
		Name:        "stub",
		BinPath:     `C:\Windows\System32\cmd.exe`,
		Account:     `NT AUTHORITY\NetworkService`,
		Password:    "",
		StartType:   StartManual,
	}
	if cfg.Account == "" {
		t.Fatal("Account field not honoured by struct literal")
	}
	if cfg.Password != "" {
		t.Fatal("Password field unexpectedly non-empty")
	}
}

// TestInstall_BuiltinAccount_PromotesToAdmin (intrusive, manual)
// installs a service under NT AUTHORITY\NetworkService — a built-in
// principal with no password — to confirm the Account+Password
// fields propagate through to mgr.Config without breaking the
// Install flow on a real SCM. Kept manual: even on admin it
// modifies SCM persistent state, which CI VMs roll back via
// snapshot.
func TestInstall_BuiltinAccount_PromotesToAdmin(t *testing.T) {
	if !user.IsAdmin() {
		t.Skip("requires elevation to talk to SCM")
	}

	name := "maldev_test_" + fmt.Sprintf("%x", rand.Int63())
	cfg := &Config{
		Name:        name,
		DisplayName: "maldev test service (P2.15)",
		BinPath:     `C:\Windows\System32\cmd.exe`,
		Args:        "/c exit",
		StartType:   StartManual,
		Account:     `NT AUTHORITY\NetworkService`,
	}
	if err := Install(cfg); err != nil {
		t.Fatalf("Install: %v", err)
	}
	defer Uninstall(name) //nolint:errcheck
	if !Exists(name) {
		t.Fatal("Exists() returned false after Install")
	}
}
