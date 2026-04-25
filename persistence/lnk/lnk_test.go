//go:build windows

package lnk

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNew(t *testing.T) {
	s := New()
	if s == nil {
		t.Fatal("New() returned nil")
	}
}

func TestBuilderChaining(t *testing.T) {
	s := New()

	got := s.
		SetTargetPath("target").
		SetArguments("args").
		SetWorkingDir("dir").
		SetIconLocation("icon").
		SetDescription("desc").
		SetHotkey("Ctrl+Alt+T").
		SetWindowStyle(StyleMinimized)

	if got != s {
		t.Fatal("builder methods must return the same pointer")
	}

	// Verify fields propagated correctly.
	if s.targetPath != "target" {
		t.Errorf("targetPath = %q, want %q", s.targetPath, "target")
	}
	if s.arguments != "args" {
		t.Errorf("arguments = %q, want %q", s.arguments, "args")
	}
	if s.workingDir != "dir" {
		t.Errorf("workingDir = %q, want %q", s.workingDir, "dir")
	}
	if s.iconLocation != "icon" {
		t.Errorf("iconLocation = %q, want %q", s.iconLocation, "icon")
	}
	if s.description != "desc" {
		t.Errorf("description = %q, want %q", s.description, "desc")
	}
	if s.hotkey != "Ctrl+Alt+T" {
		t.Errorf("hotkey = %q, want %q", s.hotkey, "Ctrl+Alt+T")
	}
	if s.windowStyle != StyleMinimized {
		t.Errorf("windowStyle = %d, want %d", s.windowStyle, StyleMinimized)
	}
	if !s.styleSet {
		t.Error("styleSet should be true after SetWindowStyle")
	}
}

func TestSave(t *testing.T) {
	dir := t.TempDir()
	lnkPath := filepath.Join(dir, "test.lnk")

	err := New().
		SetTargetPath(`C:\Windows\System32\cmd.exe`).
		SetArguments("/c echo ok").
		SetWindowStyle(StyleMinimized).
		Save(lnkPath)
	if err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	info, err := os.Stat(lnkPath)
	if err != nil {
		t.Fatalf("stat shortcut: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("shortcut file is empty")
	}
}
