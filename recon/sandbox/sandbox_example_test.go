package sandbox_test

import (
	"context"

	"github.com/oioio-space/maldev/recon/sandbox"
)

// New + IsSandboxed runs the multi-factor assessment:
// debugger + VM + hardware thresholds + suspicious user/
// hostnames + analysis-tool processes + DNS sandbox-pattern
// + time-based evasion.
func ExampleNew() {
	checker := sandbox.New(sandbox.DefaultConfig())
	sandboxed, _, err := checker.IsSandboxed(context.Background())
	if err != nil {
		return
	}
	if sandboxed {
		// bail out — sandbox detected
		return
	}
	// continue with normal beaconing
}
