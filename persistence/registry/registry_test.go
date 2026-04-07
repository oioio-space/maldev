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
