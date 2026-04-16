package bridge

import (
	"io"
	"sync"
)

// Call holds a tagged hook event sent by the Controller for approval.
type Call struct {
	Tag  string
	Data []byte
}

// Listener receives events from a hook Controller over a bidirectional
// connection. Register handlers with OnCall/OnExfil/OnLog before calling
// Serve. Call Close to stop the loop.
type Listener struct {
	conn    io.ReadWriteCloser
	onCall  func(Call) Decision
	onExfil func(tag string, data []byte)
	onLog   func(msg string)
	mu      sync.Mutex
	closed  bool
}

// NewListener wraps conn in a Listener. Call Serve in a goroutine to start
// dispatching messages.
func NewListener(conn io.ReadWriteCloser) *Listener {
	return &Listener{conn: conn}
}

// OnCall registers a handler invoked for each msgCall frame. The returned
// Decision is sent back to the Controller synchronously.
func (l *Listener) OnCall(handler func(Call) Decision) { l.onCall = handler }

// OnExfil registers a handler invoked for each msgExfil frame.
func (l *Listener) OnExfil(handler func(tag string, data []byte)) { l.onExfil = handler }

// OnLog registers a handler invoked for each msgLog frame.
func (l *Listener) OnLog(handler func(msg string)) { l.onLog = handler }

// Serve reads frames from the connection until it is closed or an error
// occurs. Returns nil after a clean Close, otherwise the read error.
func (l *Listener) Serve() error {
	for {
		msgType, payload, err := readFrame(l.conn)
		if err != nil {
			l.mu.Lock()
			closed := l.closed
			l.mu.Unlock()
			if closed {
				return nil
			}
			return err
		}
		switch msgType {
		case msgCall:
			tag, data := splitTagData(payload)
			d := Allow
			if l.onCall != nil {
				d = l.onCall(Call{Tag: tag, Data: data})
			}
			writeFrame(l.conn, msgDecision, []byte{byte(d)}) //nolint:errcheck
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
			writeFrame(l.conn, msgHeartbeat, nil) //nolint:errcheck
		}
	}
}

// Close marks the Listener as closed and shuts down the connection. A
// concurrent Serve call will return nil rather than a connection error.
func (l *Listener) Close() error {
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()
	return l.conn.Close()
}
