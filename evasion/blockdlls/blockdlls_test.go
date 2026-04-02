//go:build windows

package blockdlls

import (
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/oioio-space/maldev/testutil"
)

func TestBlockDLLsEnableInChild(t *testing.T) {
	testutil.RequireIntrusive(t)

	if os.Getenv("MALDEV_CHILD_TEST") == "blockdlls" {
		// We ARE the child — enable BlockDLLs for this process and report success.
		// The policy is irreversible so we must run in a short-lived child.
		err := Enable(nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %v", err)
			os.Exit(1)
		}
		fmt.Print("BLOCKDLLS_ENABLED")
		os.Exit(0)
	}

	// We are the parent — spawn a copy of the test binary as the child.
	cmd := exec.Command(os.Args[0], "-test.run=TestBlockDLLsEnableInChild", "-test.v")
	cmd.Env = append(os.Environ(), "MALDEV_CHILD_TEST=blockdlls", "MALDEV_INTRUSIVE=1")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "child process failed: %s", string(output))
	assert.Contains(t, string(output), "BLOCKDLLS_ENABLED")
}
