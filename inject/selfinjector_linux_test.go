//go:build linux

package inject

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSelfInjector_LinuxInjector_BeforeInject(t *testing.T) {
	inj, err := NewInjector(&Config{Method: MethodProcMem})
	require.NoError(t, err)

	si, ok := inj.(SelfInjector)
	require.True(t, ok, "linuxInjector must satisfy SelfInjector")

	r, has := si.InjectedRegion()
	assert.False(t, has, "no region before Inject has been called")
	assert.Equal(t, Region{}, r)
}

// TestSelfInjector_LinuxInjector_ProcMemSetsRegion uses the same
// child-process isolation as TestProcMemSelfInject because running the
// shellcode can corrupt the Go runtime on the way out. The child verifies
// the region contract and prints a success marker; the parent only asserts
// that marker surfaced.
func TestSelfInjector_LinuxInjector_ProcMemSetsRegion(t *testing.T) {
	if os.Getenv("MALDEV_CHILD_TEST") == "selfinjector-procmem" {
		runProcMemChild()
		return
	}

	marker := []byte("SELFINJECTOR_PROCMEM_OK")
	var output []byte
	var err error
	for attempt := 1; attempt <= 3; attempt++ {
		cmd := exec.Command(os.Args[0], "-test.run=TestSelfInjector_LinuxInjector_ProcMemSetsRegion", "-test.v")
		cmd.Env = append(os.Environ(), "MALDEV_CHILD_TEST=selfinjector-procmem")
		output, err = cmd.CombinedOutput()
		if bytes.Contains(output, marker) {
			return
		}
		t.Logf("attempt %d: child stdout lacks %q (exit=%v)", attempt, marker, err)
	}
	require.Failf(t, "child never reached the success marker", "last exit=%v, output=\n%s", err, string(output))
}

func runProcMemChild() {
	inj, err := NewInjector(&Config{Method: MethodProcMem})
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: NewInjector: %v\n", err)
		os.Exit(1)
	}
	si, ok := inj.(SelfInjector)
	if !ok {
		fmt.Fprintln(os.Stderr, "FAIL: linuxInjector does not satisfy SelfInjector")
		os.Exit(1)
	}

	sc := []byte{0x31, 0xC0, 0xC3} // xor eax,eax; ret
	if err := inj.Inject(sc); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: Inject: %v\n", err)
		os.Exit(1)
	}
	r, has := si.InjectedRegion()
	if !has {
		fmt.Fprintln(os.Stderr, "FAIL: InjectedRegion has=false after successful Inject")
		os.Exit(1)
	}
	if r.Addr == 0 {
		fmt.Fprintln(os.Stderr, "FAIL: InjectedRegion.Addr is zero")
		os.Exit(1)
	}
	if r.Size != uintptr(len(sc)) {
		fmt.Fprintf(os.Stderr, "FAIL: InjectedRegion.Size=%d want %d\n", r.Size, len(sc))
		os.Exit(1)
	}
	fmt.Print("SELFINJECTOR_PROCMEM_OK")
	// Flush stdout before the shellcode goroutine can corrupt exit cleanup.
	os.Stdout.Sync()
	os.Exit(0)
}
