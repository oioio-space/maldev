//go:build linux

package inject

import (
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/oioio-space/maldev/testutil"
)

// Linux injection tests use the child-process pattern because shellcode
// execution can crash the Go runtime's goroutine machinery (even a clean
// xor eax,eax; ret causes background faults when the mmap'd region is
// called as a function). Running in a child isolates the damage.

func TestProcMemSelfInject(t *testing.T) {
	testutil.RequireIntrusive(t)
	if os.Getenv("MALDEV_CHILD_TEST") == "procmem" {
		nopRet := []byte{0x31, 0xC0, 0xC3}
		cfg := &Config{Method: MethodProcMem}
		injector, err := NewInjector(cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %v", err)
			os.Exit(1)
		}
		if err := injector.Inject(nopRet); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %v", err)
			os.Exit(1)
		}
		fmt.Print("PROCMEM_OK")
		os.Exit(0)
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestProcMemSelfInject", "-test.v")
	cmd.Env = append(os.Environ(), "MALDEV_CHILD_TEST=procmem")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "child failed: %s", string(output))
	assert.Contains(t, string(output), "PROCMEM_OK")
}

func TestPureGoExec(t *testing.T) {
	testutil.RequireIntrusive(t)
	if os.Getenv("MALDEV_CHILD_TEST") == "purego" {
		nopRet := []byte{0x31, 0xC0, 0xC3}
		cfg := &Config{Method: MethodPureGoShellcode}
		injector, err := NewInjector(cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %v", err)
			os.Exit(1)
		}
		if err := injector.Inject(nopRet); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %v", err)
			os.Exit(1)
		}
		fmt.Print("PUREGO_OK")
		os.Exit(0)
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestPureGoExec", "-test.v")
	cmd.Env = append(os.Environ(), "MALDEV_CHILD_TEST=purego")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "child failed: %s", string(output))
	assert.Contains(t, string(output), "PUREGO_OK")
}
