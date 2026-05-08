//go:build linux

package runtime_test

import (
	"testing"

	"github.com/oioio-space/maldev/pe/packer/runtime"
)

// TestReadSelfAuxv_ContainsCanaryOverride confirms readSelfAuxv
// rewrites AT_RANDOM (type 25) to the supplied canaryPtr so the
// loaded Go runtime reads our fresh canary rather than inheriting
// the parent's stack canary.
//
// Linux-only: /proc/self/auxv has no Windows analogue, and
// runtime.ReadSelfAuxvForTest is exported only behind the linux
// build tag (see runtime_linux.go). Splitting this test into a
// linux-tagged file lets the rest of runtime_test.go compile on
// Windows / Darwin without a stub.
func TestReadSelfAuxv_ContainsCanaryOverride(t *testing.T) {
	canary := uintptr(0xCAFEBABE)
	auxv := runtime.ReadSelfAuxvForTest(canary)
	var found bool
	for _, e := range auxv {
		if e.Type == 25 { // AT_RANDOM
			if e.Val != uint64(canary) {
				t.Errorf("AT_RANDOM not overridden: got %#x, want %#x", e.Val, canary)
			}
			found = true
		}
	}
	if !found {
		t.Skip("/proc/self/auxv on this kernel doesn't carry AT_RANDOM (uncommon, no fault of ours)")
	}
}
