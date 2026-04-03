package inject

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockMemorySetup struct {
	addr uintptr
	err  error
	sc   []byte
}

func (m *mockMemorySetup) Setup(sc []byte) (uintptr, error) {
	m.sc = sc
	return m.addr, m.err
}

type mockExecutor struct {
	addr uintptr
	err  error
}

func (m *mockExecutor) Execute(addr uintptr) error {
	m.addr = addr
	return m.err
}

func TestPipeline_EmptyShellcode(t *testing.T) {
	mem := &mockMemorySetup{addr: 0x1000}
	exec := &mockExecutor{}
	p := NewPipeline(mem, exec)

	err := p.Inject([]byte{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
	assert.Nil(t, mem.sc, "Setup should not be called for empty shellcode")
}

func TestPipeline_SetupError(t *testing.T) {
	setupErr := errors.New("allocation failed")
	mem := &mockMemorySetup{err: setupErr}
	exec := &mockExecutor{}
	p := NewPipeline(mem, exec)

	err := p.Inject([]byte{0x90})
	require.Error(t, err)
	assert.ErrorIs(t, err, setupErr)
	assert.Contains(t, err.Error(), "memory setup")
	assert.Equal(t, uintptr(0), exec.addr, "Executor should not be called on setup error")
}

func TestPipeline_ExecuteError(t *testing.T) {
	execErr := errors.New("thread creation failed")
	mem := &mockMemorySetup{addr: 0x2000}
	exec := &mockExecutor{err: execErr}
	p := NewPipeline(mem, exec)

	err := p.Inject([]byte{0x90})
	require.Error(t, err)
	assert.ErrorIs(t, err, execErr)
	assert.Contains(t, err.Error(), "execute")
}

func TestPipeline_Success(t *testing.T) {
	sc := []byte{0xCC, 0x90, 0xC3}
	mem := &mockMemorySetup{addr: 0x3000}
	exec := &mockExecutor{}
	p := NewPipeline(mem, exec)

	err := p.Inject(sc)
	require.NoError(t, err)

	// Verify Setup received the shellcode.
	assert.Equal(t, sc, mem.sc)

	// Verify Executor received the address from Setup.
	assert.Equal(t, uintptr(0x3000), exec.addr)
}
