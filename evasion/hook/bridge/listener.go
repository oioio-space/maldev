package bridge

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
)

// Call holds a tagged hook event sent by the Controller for approval.
type Call struct {
	Tag  string
	Data []byte
}

// Listener receives events from a hook Controller and sends RPC commands.
// Register event handlers with OnCall/OnExfil/OnLog before calling Serve.
type Listener struct {
	conn    io.ReadWriteCloser
	onCall  func(Call) Decision
	onExfil func(tag string, data []byte)
	onLog   func(msg string)

	pending map[uint32]chan rpcResponse
	nextID  atomic.Uint32
	mu      sync.Mutex
	writeMu sync.Mutex
	closed  bool
}

// NewListener wraps conn in a Listener.
func NewListener(conn io.ReadWriteCloser) *Listener {
	return &Listener{
		conn:    conn,
		pending: make(map[uint32]chan rpcResponse),
	}
}

// OnCall registers a handler for hook call events.
func (l *Listener) OnCall(handler func(Call) Decision) { l.onCall = handler }

// OnExfil registers a handler for data exfiltration events.
func (l *Listener) OnExfil(handler func(tag string, data []byte)) { l.onExfil = handler }

// OnLog registers a handler for log messages.
func (l *Listener) OnLog(handler func(msg string)) { l.onLog = handler }

// Call sends an RPC command to the handler and waits for the response.
func (l *Listener) Call(name string, data []byte) ([]byte, error) {
	reqID := l.nextID.Add(1)
	ch := make(chan rpcResponse, 1)
	l.mu.Lock()
	l.pending[reqID] = ch
	l.mu.Unlock()

	payload := append([]byte(name+"\x00"), data...)
	if err := l.lockedWriteWithID(msgCommand, reqID, payload); err != nil {
		l.removePending(reqID)
		return nil, fmt.Errorf("send command %q: %w", name, err)
	}

	resp := <-ch
	if resp.err != nil {
		return nil, resp.err
	}
	if len(resp.data) > 4 && string(resp.data[:4]) == "ERR:" {
		return nil, fmt.Errorf("remote: %s", resp.data[4:])
	}
	return resp.data, nil
}

// ReadMemory sends a built-in read_memory command to the handler.
func (l *Listener) ReadMemory(addr uintptr, size uint32) ([]byte, error) {
	buf := make([]byte, 12)
	binary.LittleEndian.PutUint64(buf[0:], uint64(addr))
	binary.LittleEndian.PutUint32(buf[8:], size)
	return l.Call("read_memory", buf)
}

// Unhook sends a built-in unhook command to the handler.
func (l *Listener) Unhook(funcName string) error {
	_, err := l.Call("unhook", []byte(funcName))
	return err
}

// Serve reads frames from the Controller in a loop. Dispatches hook events
// to registered handlers and routes RPC responses to pending Call requests.
func (l *Listener) Serve() error {
	for {
		msgType, reqID, payload, err := readFrameWithID(l.conn)
		if err != nil {
			l.mu.Lock()
			closed := l.closed
			l.mu.Unlock()
			if closed {
				l.drainPending(fmt.Errorf("listener closed"))
				return nil
			}
			l.drainPending(err)
			return err
		}

		switch msgType {
		case msgCall:
			tag, data := splitTagData(payload)
			d := Allow
			if l.onCall != nil {
				d = l.onCall(Call{Tag: tag, Data: data})
			}
			l.lockedWriteWithID(msgDecision, reqID, []byte{byte(d)})

		case msgResponse:
			l.mu.Lock()
			ch, ok := l.pending[reqID]
			if ok {
				delete(l.pending, reqID)
			}
			l.mu.Unlock()
			if ok {
				ch <- rpcResponse{data: payload}
			}

		case msgExfil:
			tag, data := splitTagData(payload)
			if l.onExfil != nil {
				l.onExfil(tag, data)
			}

		case msgLog:
			if l.onLog != nil {
				l.onLog(string(payload))
			}

		case msgHeartbeat:
			l.lockedWriteWithID(msgHeartbeat, reqID, nil)
		}
	}
}

// Close stops the listener and unblocks pending RPCs.
func (l *Listener) Close() error {
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()
	l.drainPending(fmt.Errorf("listener closed"))
	return l.conn.Close()
}

func (l *Listener) lockedWriteWithID(msgType byte, reqID uint32, payload []byte) error {
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	return writeFrameWithID(l.conn, msgType, reqID, payload)
}

func (l *Listener) removePending(reqID uint32) {
	l.mu.Lock()
	delete(l.pending, reqID)
	l.mu.Unlock()
}

func (l *Listener) drainPending(err error) {
	l.mu.Lock()
	for id, ch := range l.pending {
		ch <- rpcResponse{err: err}
		delete(l.pending, id)
	}
	l.mu.Unlock()
}
