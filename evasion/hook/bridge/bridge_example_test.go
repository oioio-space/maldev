package bridge_test

import (
	"github.com/oioio-space/maldev/evasion/hook/bridge"
)

// Standalone returns a Controller that operates without any IPC —
// useful when the hook decision is hard-coded (e.g., always block
// MessageBoxW). The handler shellcode runs autonomously with no
// runtime swap path.
func ExampleStandalone() {
	ctrl := bridge.Standalone()
	_ = ctrl
}

// Connect wires the Controller to an io.ReadWriteCloser transport
// — typically a c2/transport/namedpipe connection or a TCP socket.
// The implant drives commands through the returned Controller and
// the hook handler obeys them at runtime.
func ExampleConnect() {
	// transport, _ := namedpipe.Dial(`\\.\pipe\hookbridge`)
	// ctrl := bridge.Connect(transport)
	// _ = ctrl
}
