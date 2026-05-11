package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureStdout runs fn and returns whatever it printed to os.Stdout
// during the call. Used by the round-diff test to assert on the
// rendered table without invoking go-test's `os.Args` mutation.
func captureStdout(t *testing.T, fn func() int) (string, int) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	old := os.Stdout
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = old })
	rc := fn()
	w.Close()
	buf := make([]byte, 0, 4096)
	chunk := make([]byte, 1024)
	for {
		n, err := r.Read(chunk)
		buf = append(buf, chunk[:n]...)
		if err != nil {
			break
		}
	}
	return string(buf), rc
}

func TestRunRoundDiff_PrintsPerRoundTable(t *testing.T) {
	in := filepath.Join(t.TempDir(), "in.bin")
	if err := os.WriteFile(in, []byte("ABCDEFGHIJKLMNOP"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	out, rc := captureStdout(t, func() int {
		return runRoundDiff([]string{"-rounds", "3", "-seed", "42", in})
	})
	if rc != 0 {
		t.Fatalf("runRoundDiff exit=%d, want 0\noutput:\n%s", rc, out)
	}

	// Header line must mention the key + size.
	if !strings.Contains(out, "16 bytes") {
		t.Errorf("missing 16 bytes in header — got:\n%s", out)
	}
	if !strings.Contains(out, "seed=42 rounds=3") {
		t.Errorf("missing seed=42 rounds=3 — got:\n%s", out)
	}

	// 3 round rows must be present (one for each round 0..2).
	for _, want := range []string{"\n    0 | ", "\n    1 | ", "\n    2 | "} {
		if !strings.Contains(out, want) {
			t.Errorf("missing round line %q — got:\n%s", want, out)
		}
	}
}

func TestRunRoundDiff_RejectsMissingPath(t *testing.T) {
	rc := runRoundDiff([]string{"-rounds", "2"})
	if rc != 2 {
		t.Errorf("missing path → rc=%d, want 2", rc)
	}
}

func TestRunRoundDiff_RejectsBadFile(t *testing.T) {
	rc := runRoundDiff([]string{"/does/not/exist/maldev-packer-vis-test"})
	if rc != 1 {
		t.Errorf("bad path → rc=%d, want 1", rc)
	}
}

func TestRunRoundDiff_DeterministicBySeed(t *testing.T) {
	in := filepath.Join(t.TempDir(), "x.bin")
	if err := os.WriteFile(in, []byte("hello world!1234"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	a, _ := captureStdout(t, func() int {
		return runRoundDiff([]string{"-rounds", "2", "-seed", "777", in})
	})
	b, _ := captureStdout(t, func() int {
		return runRoundDiff([]string{"-rounds", "2", "-seed", "777", in})
	})
	if a != b {
		t.Errorf("identical seed should produce identical output\nA:\n%s\nB:\n%s", a, b)
	}
}
