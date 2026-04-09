//go:build windows

package registry

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
)

// testValueName generates a unique registry value name to avoid test collisions.
func testValueName(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("generate random name: %v", err)
	}
	return "maldev_test_" + hex.EncodeToString(b)
}

func TestSetAndGet(t *testing.T) {
	name := testValueName(t)
	value := `C:\Windows\System32\notepad.exe`

	defer func() {
		_ = Delete(HiveCurrentUser, KeyRun, name)
	}()

	if err := Set(HiveCurrentUser, KeyRun, name, value); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := Get(HiveCurrentUser, KeyRun, name)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != value {
		t.Fatalf("Get returned %q, want %q", got, value)
	}
}

func TestDelete(t *testing.T) {
	name := testValueName(t)

	defer func() {
		_ = Delete(HiveCurrentUser, KeyRun, name)
	}()

	if err := Set(HiveCurrentUser, KeyRun, name, "test"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if err := Delete(HiveCurrentUser, KeyRun, name); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	exists, err := Exists(HiveCurrentUser, KeyRun, name)
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if exists {
		t.Fatal("Exists returned true after Delete")
	}
}

func TestExists(t *testing.T) {
	name := testValueName(t)

	exists, err := Exists(HiveCurrentUser, KeyRun, name)
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if exists {
		t.Fatal("Exists returned true for non-existent value")
	}
}

func TestGetNotFound(t *testing.T) {
	name := testValueName(t)

	_, err := Get(HiveCurrentUser, KeyRun, name)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get returned %v, want ErrNotFound", err)
	}
}

func TestRunKeyReturnsValidMechanism(t *testing.T) {
	m := RunKey(HiveCurrentUser, KeyRun, "maldev_test_mech", `C:\test.exe`)

	if m == nil {
		t.Fatal("RunKey returned nil")
	}
	if m.Name() != "registry:HKCU:Run" {
		t.Fatalf("Name() = %q, want %q", m.Name(), "registry:HKCU:Run")
	}
}

func TestRunKeyNameVariants(t *testing.T) {
	tests := []struct {
		hive     Hive
		keyType  KeyType
		wantName string
	}{
		{HiveCurrentUser, KeyRun, "registry:HKCU:Run"},
		{HiveCurrentUser, KeyRunOnce, "registry:HKCU:RunOnce"},
		{HiveLocalMachine, KeyRun, "registry:HKLM:Run"},
		{HiveLocalMachine, KeyRunOnce, "registry:HKLM:RunOnce"},
	}
	for _, tc := range tests {
		m := RunKey(tc.hive, tc.keyType, "test", "test")
		if m.Name() != tc.wantName {
			t.Errorf("RunKey(%d,%d).Name() = %q, want %q", tc.hive, tc.keyType, m.Name(), tc.wantName)
		}
	}
}

func TestExistsNonExistent(t *testing.T) {
	name := testValueName(t)
	exists, err := Exists(HiveCurrentUser, KeyRun, name)
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if exists {
		t.Fatal("Exists returned true for a random non-existent value")
	}
}

func TestExistsRunOnceNonExistent(t *testing.T) {
	name := testValueName(t)
	exists, err := Exists(HiveCurrentUser, KeyRunOnce, name)
	if err != nil {
		t.Fatalf("Exists (RunOnce): %v", err)
	}
	if exists {
		t.Fatal("Exists returned true for a random non-existent RunOnce value")
	}
}

func TestRunKeyInstalledReturnsFalseForMissing(t *testing.T) {
	name := testValueName(t)
	m := RunKey(HiveCurrentUser, KeyRun, name, `C:\fake.exe`)
	installed, err := m.Installed()
	if err != nil {
		t.Fatalf("Installed: %v", err)
	}
	if installed {
		t.Fatal("Installed returned true for a value that was never set")
	}
}

func TestKeyPath(t *testing.T) {
	run := keyPath(KeyRun)
	if run != `Software\Microsoft\Windows\CurrentVersion\Run` {
		t.Fatalf("keyPath(KeyRun) = %q", run)
	}
	runOnce := keyPath(KeyRunOnce)
	if runOnce != `Software\Microsoft\Windows\CurrentVersion\RunOnce` {
		t.Fatalf("keyPath(KeyRunOnce) = %q", runOnce)
	}
}
