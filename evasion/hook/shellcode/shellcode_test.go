package shellcode

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBlock(t *testing.T) {
	sc := Block()
	require.Equal(t, []byte{0x31, 0xC0, 0xC3}, sc)
	require.Len(t, sc, 3)
}

func TestNop(t *testing.T) {
	addr := uintptr(0x00007FF612340000)
	sc := Nop(addr)
	require.Len(t, sc, 13)
	require.Equal(t, byte(0x49), sc[0])
	require.Equal(t, byte(0xBA), sc[1])
	decoded := binary.LittleEndian.Uint64(sc[2:10])
	require.Equal(t, uint64(addr), decoded)
	require.Equal(t, byte(0x41), sc[10])
	require.Equal(t, byte(0xFF), sc[11])
	require.Equal(t, byte(0xE2), sc[12])
}

func TestReplace(t *testing.T) {
	sc := Replace(0x42)
	require.Len(t, sc, 11)
	require.Equal(t, byte(0x48), sc[0])
	require.Equal(t, byte(0xB8), sc[1])
	decoded := binary.LittleEndian.Uint64(sc[2:10])
	require.Equal(t, uint64(0x42), decoded)
	require.Equal(t, byte(0xC3), sc[10])
}

func TestRedirect(t *testing.T) {
	addr := uintptr(0xDEAD)
	sc := Redirect(addr)
	require.Len(t, sc, 13)
	decoded := binary.LittleEndian.Uint64(sc[2:10])
	require.Equal(t, uint64(addr), decoded)
}

func TestReplaceZero(t *testing.T) {
	sc := Replace(0)
	require.Len(t, sc, 11)
	decoded := binary.LittleEndian.Uint64(sc[2:10])
	require.Equal(t, uint64(0), decoded)
}
