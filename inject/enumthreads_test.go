//go:build windows && amd64

package inject

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindAllThreadsNt(t *testing.T) {
	pid := os.Getpid()
	threads, err := FindAllThreadsNt(pid, nil)
	require.NoError(t, err)
	assert.Greater(t, len(threads), 0, "current process must have at least one thread")
}

func TestFindAllThreadsNt_InvalidPID(t *testing.T) {
	_, err := FindAllThreadsNt(0, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid")
}

func TestFindAllThreadsNt_NonExistentPID(t *testing.T) {
	// PID 99999999 is extremely unlikely to exist.
	_, err := FindAllThreadsNt(99999999, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}
