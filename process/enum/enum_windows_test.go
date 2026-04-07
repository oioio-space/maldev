//go:build windows

package enum

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestThreads(t *testing.T) {
	// Current process should have at least one thread.
	pid := uint32(os.Getpid())
	threads, err := Threads(pid)
	require.NoError(t, err)
	assert.NotEmpty(t, threads, "current process should have threads")
}
