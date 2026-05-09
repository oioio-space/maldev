package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

// cachedLauncherPath is the build-once path for a no-ldflags
// bundle-launcher binary, shared across every E2E test in this
// package that doesn't need a per-secret build.
//
// The previous pattern rebuilt the launcher from source on every
// test (~1 second each); a 4-test file took ~4 seconds before the
// first byte of payload bytes ran. sync.Once + a package-level
// path collapses identical-args builds into one.
//
// Tests using -ldflags '-X main.bundleSecret=...' can NOT share
// this cache (their output bytes are secret-specific) — they keep
// building inline.
var (
	cachedLauncherOnce  sync.Once
	cachedLauncherPath  string
	cachedLauncherErr   error
	cachedLauncherBytes []byte
)

// sharedLauncher returns (path, bytes) for the no-ldflags
// bundle-launcher binary. Builds it once per test process; subsequent
// callers get the cached output. Bytes are read once for callers
// that pass them to packer.AppendBundle / AppendBundleWith without
// having to re-read from disk.
func sharedLauncher(t *testing.T) (string, []byte) {
	t.Helper()
	cachedLauncherOnce.Do(func() {
		dir, err := os.MkdirTemp("", "bundle-launcher-cache-*")
		if err != nil {
			cachedLauncherErr = err
			return
		}
		path := filepath.Join(dir, "bundle-launcher")
		out, err := exec.Command("go", "build", "-o", path,
			"github.com/oioio-space/maldev/cmd/bundle-launcher",
		).CombinedOutput()
		if err != nil {
			cachedLauncherErr = err
			t.Logf("sharedLauncher build failed: %v\n%s", err, out)
			return
		}
		bytes, err := os.ReadFile(path)
		if err != nil {
			cachedLauncherErr = err
			return
		}
		cachedLauncherPath = path
		cachedLauncherBytes = bytes
	})
	if cachedLauncherErr != nil {
		t.Fatalf("sharedLauncher: %v", cachedLauncherErr)
	}
	return cachedLauncherPath, cachedLauncherBytes
}
