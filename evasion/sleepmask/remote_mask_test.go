package sleepmask

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRemote(t *testing.T) {
	m := NewRemote(RemoteRegion{Handle: 0xBEEF, Addr: 0x1000, Size: 4096})
	require.NotNil(t, m)
	_, ok := m.cipher.(*XORCipher)
	assert.True(t, ok)
	_, ok = m.strategy.(*RemoteInlineStrategy)
	assert.True(t, ok)
}

func TestRemoteMask_WithCipher_Nil(t *testing.T) {
	m := NewRemote().WithCipher(nil)
	_, ok := m.cipher.(*XORCipher)
	assert.True(t, ok)
}

func TestRemoteMask_WithStrategy_Nil(t *testing.T) {
	m := NewRemote().WithStrategy(nil)
	_, ok := m.strategy.(*RemoteInlineStrategy)
	assert.True(t, ok)
}
