//go:build windows

package lnk

import (
	"bytes"
	"io"
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

func TestBuildBytes(t *testing.T) {
	b, err := New().
		SetTargetPath(`C:\Windows\System32\cmd.exe`).
		SetArguments("/c echo ok").
		SetWindowStyle(StyleMinimized).
		BuildBytes()
	if err != nil {
		t.Fatalf("BuildBytes() error: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("BuildBytes() returned 0 bytes")
	}
	// Shell link header: 4-byte HeaderSize == 0x4C, followed by
	// the LinkCLSID 00021401-0000-0000-C000-000000000046.
	if b[0] != 0x4C {
		t.Errorf("HeaderSize byte = 0x%02x, want 0x4C", b[0])
	}
}

func TestWriteTo(t *testing.T) {
	var buf bytes.Buffer
	n, err := New().
		SetTargetPath(`C:\Windows\System32\cmd.exe`).
		SetWindowStyle(StyleMinimized).
		WriteTo(&buf)
	if err != nil {
		t.Fatalf("WriteTo() error: %v", err)
	}
	if n == 0 || int64(buf.Len()) != n {
		t.Fatalf("WriteTo() n=%d, buf.Len=%d", n, buf.Len())
	}
}

func TestSetIconLocationIndexed(t *testing.T) {
	s := New().SetIconLocationIndexed(`C:\Windows\System32\shell32.dll`, 3)
	if s.iconLocation != `C:\Windows\System32\shell32.dll,3` {
		t.Errorf("iconLocation = %q", s.iconLocation)
	}
}

func TestParseHotkey(t *testing.T) {
	cases := []struct {
		in   string
		want uint16
		ok   bool
	}{
		{"", 0, false},
		{"Ctrl+Alt+T", 0x06<<8 | 'T', true},   // Ctrl(0x02)|Alt(0x04) = 0x06
		{"Shift+F1", 0x01<<8 | 0x70, true},    // Shift; VK_F1=0x70
		{"Alt+1", 0x04<<8 | '1', true},        // Alt; '1' = 0x31
		{"Control+A", 0x02<<8 | 'A', true},    // long-form Control alias
		{"Ctrl+F25", 0, false},                // out of range
		{"Ctrl+@", 0, false},                  // unsupported key
		{"OnlyMods+Ctrl+Alt", 0, false},       // no key (token "OnlyMods" rejected as key)
	}
	for _, c := range cases {
		got, ok := parseHotkey(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("parseHotkey(%q) = (0x%04x, %v), want (0x%04x, %v)",
				c.in, got, ok, c.want, c.ok)
		}
	}
}

// recordingCreator captures Create calls so WriteVia delegation can be
// asserted without hitting the filesystem with the operator's primitive.
type recordingCreator struct {
	paths []string
	buf   bytes.Buffer
}

func (r *recordingCreator) Create(path string) (io.WriteCloser, error) {
	r.paths = append(r.paths, path)
	return nopWriteCloser{&r.buf}, nil
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

func TestWriteVia_NilUsesStandardCreator(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "via.lnk")
	if err := New().
		SetTargetPath(`C:\Windows\System32\cmd.exe`).
		SetWindowStyle(StyleMinimized).
		WriteVia(nil, path); err != nil {
		t.Fatalf("WriteVia(nil): %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("written .lnk is empty")
	}
}

func TestWriteVia_DelegatesToCreator(t *testing.T) {
	rc := &recordingCreator{}
	const path = `C:\fake\path\out.lnk`
	if err := New().
		SetTargetPath(`C:\Windows\System32\cmd.exe`).
		WriteVia(rc, path); err != nil {
		t.Fatalf("WriteVia: %v", err)
	}
	if len(rc.paths) != 1 || rc.paths[0] != path {
		t.Errorf("Create paths = %v, want [%q]", rc.paths, path)
	}
	if rc.buf.Len() == 0 {
		t.Error("recordingCreator received zero bytes")
	}
}

func TestBuildBytesNoArtefact(t *testing.T) {
	// Snapshot %TEMP% before / after to confirm BuildBytes leaves no
	// `maldev-lnk-*` directory behind on the success path.
	before, _ := filepath.Glob(filepath.Join(os.TempDir(), "maldev-lnk-*"))
	if _, err := New().
		SetTargetPath(`C:\Windows\System32\cmd.exe`).
		BuildBytes(); err != nil {
		t.Fatalf("BuildBytes() error: %v", err)
	}
	after, _ := filepath.Glob(filepath.Join(os.TempDir(), "maldev-lnk-*"))
	if len(after) > len(before) {
		t.Errorf("BuildBytes left %d residual temp dir(s)", len(after)-len(before))
	}
}
