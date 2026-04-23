//go:build windows

package inject

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/oioio-space/maldev/evasion/stealthopen"
)

type phantomSpyOpener struct {
	inner stealthopen.Opener
	calls atomic.Int32
	paths []string
}

func (s *phantomSpyOpener) Open(path string) (*os.File, error) {
	s.calls.Add(1)
	s.paths = append(s.paths, path)
	if s.inner == nil {
		s.inner = &stealthopen.Standard{}
	}
	return s.inner.Open(path)
}

// TestPhantomDLLInject_UsesProvidedOpener confirms the new Opener flows
// through the injection path. PID 1 is invalid for OpenProcess so the
// injection fails deep — but only AFTER the opener has been consulted
// twice (once for PE parse, once for the section handle). Both calls
// must target the same System32 DLL path.
func TestPhantomDLLInject_UsesProvidedOpener(t *testing.T) {
	spy := &phantomSpyOpener{}
	_ = PhantomDLLInject(1, "ntdll.dll", []byte{0x90, 0xC3}, spy)

	// PhantomDLLInject(pid=1, ...) will fail at OpenProcess, but only
	// after doing both opens through the Opener. Expect exactly 2 opens
	// on the same ntdll.dll path.
	assert.Equal(t, int32(2), spy.calls.Load(),
		"opener must be consulted exactly twice (PE parse + section handle)")
	if len(spy.paths) >= 1 {
		assert.Equal(t, "ntdll.dll", filepath.Base(spy.paths[0]))
	}
	if len(spy.paths) >= 2 {
		assert.Equal(t, spy.paths[0], spy.paths[1],
			"both opens must target the same path")
	}
}
