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
	cmd := exec.Command(bin, "--op="+op)
	out, err := cmd.CombinedOutput()
	t.Logf("clrhost --op=%s exit=%v\noutput:\n%s", op, err, out)
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

	cmd := exec.Command("go", "build", "-o", exe, "./testutil/clrhost")
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
