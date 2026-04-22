//go:build windows

package testutil

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// RunCLROperation spawns the committed clrhost helper binary with the
// requested --op flag. The helper ships with an <exe>.config enabling
// legacy v2 CLR activation, so mscoree honours the ICorRuntimeHost path
// that a plain `go test` binary cannot reach on Windows 10+.
//
// Exit code 2 (pe/clr.Load failed — typically because .NET 3.5 is not
// installed) is mapped to t.Skip. Any other non-zero exit bubbles up as
// a test failure.
//
// Valid operations: "load", "exec-empty", "exec-dll-validation".
// See testutil/clrhost/main.go for their semantics.
func RunCLROperation(t *testing.T, op string) error {
	t.Helper()
	bin := requireClrhost(t)
	args := []string{"--op=" + op}
	// exec-dll-real needs a real managed assembly. We ship a committed
	// 3 KB .NET 2.0 DLL next to clrhost's source; resolve its path via
	// moduleRoot so the helper doesn't depend on CWD.
	if op == "exec-dll-real" {
		root, err := moduleRoot()
		if err != nil {
			t.Skipf("module root: %v", err)
		}
		args = append(args, "--dll-path="+filepath.Join(root, "testutil", "clrhost", "maldev_clr_test.dll"))
	}
	cmd := exec.Command(bin, args...)
	// Point the cover-instrumented binary at our accumulating covdata dir.
	// Each invocation appends its hit counts; the textfmt pass below
	// rewrites clrCoverOut with the cumulative union.
	if clrCoverDir != "" {
		cmd.Env = append(os.Environ(), "GOCOVERDIR="+clrCoverDir)
	}
	out, err := cmd.CombinedOutput()
	t.Logf("clrhost --op=%s exit=%v\noutput:\n%s", op, err, out)
	// Refresh the textfmt profile regardless of exit code — a crashing
	// clrhost still emits partial covdata that's worth keeping.
	clrhostExportProfile()
	if err == nil {
		return nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == 2 {
		// Environmental miss (no .NET 3.5, CLR legacy blocked): skip instead of fail.
		t.Skipf("clrhost reports CLR unavailable:\n%s", strings.TrimSpace(string(out)))
	}
	return err
}

// clrhostExportProfile converts accumulated covdata binary files in
// clrCoverDir to a textfmt profile at clrCoverOut, which the host-side
// vmtest Fetch can pull back. Best-effort: any failure (no go toolchain,
// empty covdata) is silently ignored to keep the test path green.
func clrhostExportProfile() {
	if clrCoverDir == "" || clrCoverOut == "" {
		return
	}
	// go tool covdata textfmt needs at least one meta+counter pair; an
	// empty dir produces a harmless exit-1 that we swallow.
	entries, err := os.ReadDir(clrCoverDir)
	if err != nil || len(entries) == 0 {
		return
	}
	_ = exec.Command("go", "tool", "covdata", "textfmt",
		"-i", clrCoverDir, "-o", clrCoverOut).Run()
}

var (
	clrhostOnce sync.Once
	clrhostBin  string
	clrhostErr  error
)

// requireClrhost builds + prepares the clrhost helper on first call,
// skips the test if the preparation fails (e.g. go toolchain missing).
func requireClrhost(t *testing.T) string {
	t.Helper()
	clrhostOnce.Do(buildClrhost)
	if clrhostErr != nil {
		t.Skipf("clrhost helper unavailable: %v", clrhostErr)
	}
	return clrhostBin
}

// clrCoverDir holds the GOCOVERDIR used by every clrhost invocation. Built
// binaries drop binary covdata files there; RunCLROperation post-processes
// them to textfmt into clrCoverOut, which the host-side vmtest Fetch pulls
// back alongside the main cover.out.
var (
	clrCoverDir string
	clrCoverOut string
	clrCoverOnce sync.Once
)

// clrhostCoverageSetup chooses stable filesystem paths for GOCOVERDIR +
// the converted textfmt output. Paths live in the system temp dir on
// purpose: both the VM and the host can reach them, and they survive
// between RunCLROperation calls so covdata accumulates.
func clrhostCoverageSetup() {
	clrCoverOnce.Do(func() {
		tmp := os.TempDir()
		clrCoverDir = filepath.Join(tmp, "maldev-clrhost-covdata")
		// The VMs pin the output file under C:/Users/Public so vmtest's
		// Fetch can pull it; on the host we stay in tmp which is fine
		// (nothing fetches host-side runs).
		if runtime.GOOS == "windows" {
			clrCoverOut = `C:\Users\Public\clrhost-cover.out`
		} else {
			clrCoverOut = filepath.Join(tmp, "clrhost-cover.out")
		}
		_ = os.MkdirAll(clrCoverDir, 0o755)
	})
}

func buildClrhost() {
	root, err := moduleRoot()
	if err != nil {
		clrhostErr = err
		return
	}
	buildDir := filepath.Join(os.TempDir(), "maldev-clrhost")
	if err := os.MkdirAll(buildDir, 0o755); err != nil {
		clrhostErr = fmt.Errorf("mkdir %s: %w", buildDir, err)
		return
	}
	exe := filepath.Join(buildDir, "clrhost.exe")

	clrhostCoverageSetup()
	// -cover makes the compiled binary emit per-function hit counts into
	// $GOCOVERDIR on every exit. The overhead is a few percent and the
	// covdata merges cleanly with the main test profile via textfmt.
	cmd := exec.Command("go", "build", "-cover", "-covermode=atomic", "-o", exe, "./testutil/clrhost")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		clrhostErr = fmt.Errorf("go build clrhost: %s: %w", string(out), err)
		return
	}

	// The committed legacy-v2 manifest must travel next to the exe —
	// mscoree reads <exe>.config at startup, so copy it each build.
	cfgSrc := filepath.Join(root, "testutil", "clrhost", "clrhost.exe.config")
	data, err := os.ReadFile(cfgSrc)
	if err != nil {
		clrhostErr = fmt.Errorf("read %s: %w", cfgSrc, err)
		return
	}
	if err := os.WriteFile(exe+".config", data, 0o644); err != nil {
		clrhostErr = fmt.Errorf("write %s.config: %w", exe, err)
		return
	}
	clrhostBin = exe
}

// moduleRoot walks up from this source file until it finds a go.mod.
func moduleRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("go.mod not found walking up from " + file)
		}
		dir = parent
	}
}
