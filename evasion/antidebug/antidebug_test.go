package antidebug

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsDebuggerPresentNoDebugger(t *testing.T) {
	// In a normal go test run the process is not traced by a debugger,
	// so this should reliably return false.
	assert.False(t, IsDebuggerPresent(), "IsDebuggerPresent() should return false in a plain test run")
}
