//go:build windows

package selfdelete

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/oioio-space/maldev/testutil"
)

func TestRunWithScriptInChild(t *testing.T) {
	testutil.RequireIntrusive(t)

	if os.Getenv("MALDEV_CHILD_TEST") == "selfdelete" {
		// We ARE the child copy — start the deletion batch script, then exit.
		// RunWithScript spawns cmd.exe to delete us after we terminate.
		err := RunWithScript(0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %v", err)
			os.Exit(1)
		}
		fmt.Print("SELFDELETE_STARTED")
		os.Exit(0)
	}

	// Parent: copy the test binary to a temp directory and run the copy.
	dir := t.TempDir()
	src := os.Args[0]
	dst := filepath.Join(dir, "deleteme.exe")

	data, err := os.ReadFile(src)
	require.NoError(t, err, "read test binary")
	require.NoError(t, os.WriteFile(dst, data, 0755), "write child binary")

	cmd := exec.Command(dst, "-test.run=TestRunWithScriptInChild", "-test.v")
	cmd.Env = append(os.Environ(), "MALDEV_CHILD_TEST=selfdelete", "MALDEV_INTRUSIVE=1")
	output, _ := cmd.CombinedOutput()

	// The batch script deletes the binary asynchronously after the child exits.
	// Give cmd.exe time to complete its deletion loop.
	time.Sleep(3 * time.Second)

	_, statErr := os.Stat(dst)
	assert.True(t, os.IsNotExist(statErr),
		"binary should have been deleted by RunWithScript, output: %s", string(output))
}
