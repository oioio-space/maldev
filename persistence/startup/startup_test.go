//go:build windows

package startup

import (
	"os"
	"testing"
)

func TestUserDir(t *testing.T) {
	dir, err := UserDir()
	if err != nil {
		t.Fatalf("UserDir: %v", err)
	}
	if dir == "" {
		t.Fatal("UserDir returned empty string")
	}

	// Verify the directory exists on the filesystem.
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat(%q): %v", dir, err)
	}
	if !info.IsDir() {
		t.Fatalf("%q is not a directory", dir)
	}
}

func TestInstallAndRemove(t *testing.T) {
	const name = "maldev_test_startup"

	// Clean up in case a previous test run left debris.
	defer func() {
		_ = Remove(name)
	}()

	// Install a shortcut pointing at notepad (safe, always present).
	if err := Install(name, `C:\Windows\System32\notepad.exe`, ""); err != nil {
		t.Fatalf("Install: %v", err)
	}

	if !Exists(name) {
		t.Fatal("Exists returned false after Install")
	}

	if err := Remove(name); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	if Exists(name) {
		t.Fatal("Exists returned true after Remove")
	}
}
