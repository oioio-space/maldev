package antidebug_test

import (
	"fmt"

	"github.com/oioio-space/maldev/recon/antidebug"
)

// IsDebuggerPresent returns true when a debugger is attached
// to the current process — Windows checks PEB BeingDebugged,
// Linux reads /proc/self/status TracerPid.
func ExampleIsDebuggerPresent() {
	if antidebug.IsDebuggerPresent() {
		fmt.Println("debugger detected — exiting")
		return
	}
}
