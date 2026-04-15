//go:build !windows

package testutil

import (
	"errors"
	"testing"
)

// RunCLROperation is Windows-only.
func RunCLROperation(t *testing.T, op string) error {
	t.Helper()
	t.Skip("RunCLROperation: Windows only")
	return errors.New("unreachable")
}
