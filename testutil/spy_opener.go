package testutil

import (
	"os"
	"sync"
	"sync/atomic"

	"github.com/oioio-space/maldev/evasion/stealthopen"
)

// SpyOpener wraps a stealthopen.Opener and records every Open call, for
// tests that need to prove a code path consulted its injected Opener
// instead of bypassing it. Inner defaults to stealthopen.Standard{}
// when nil so tests can skip plumbing a real strategy when they only
// care about call-count / last-path assertions.
type SpyOpener struct {
	Inner stealthopen.Opener

	Calls atomic.Int32

	mu    sync.Mutex
	paths []string
}

// Open implements stealthopen.Opener. Safe under concurrent use.
func (s *SpyOpener) Open(path string) (*os.File, error) {
	s.Calls.Add(1)
	s.mu.Lock()
	s.paths = append(s.paths, path)
	s.mu.Unlock()
	inner := s.Inner
	if inner == nil {
		inner = &stealthopen.Standard{}
	}
	return inner.Open(path)
}

// Paths returns a snapshot of every path passed to Open so far.
func (s *SpyOpener) Paths() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.paths))
	copy(out, s.paths)
	return out
}

// Last returns the most recent path passed to Open, or "" if no calls.
func (s *SpyOpener) Last() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.paths) == 0 {
		return ""
	}
	return s.paths[len(s.paths)-1]
}
