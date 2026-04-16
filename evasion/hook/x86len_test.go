package hook

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCalcStealLength(t *testing.T) {
	// sub rsp, 0x28 (4 bytes) + mov [rsp+30h], rbx (5 bytes)
	prologue := []byte{
		0x48, 0x83, 0xEC, 0x28,
		0x48, 0x89, 0x5C, 0x24, 0x30,
		0x48, 0x89, 0x74, 0x24, 0x38,
	}
	length, err := calcStealLength(prologue, 5)
	require.NoError(t, err)
	require.Equal(t, 9, length)
}

func TestCalcStealLengthExact(t *testing.T) {
	// push rbp (1) + mov rbp, rsp (3) + push rbx (1) = exactly 5
	prologue := []byte{
		0x55,
		0x48, 0x89, 0xE5,
		0x53,
		0x48, 0x83, 0xEC, 0x20,
	}
	length, err := calcStealLength(prologue, 5)
	require.NoError(t, err)
	require.Equal(t, 5, length)
}

func TestCalcStealLengthTooShort(t *testing.T) {
	prologue := []byte{0xCC, 0xCC, 0xCC}
	_, err := calcStealLength(prologue, 5)
	require.Error(t, err)
}

func TestDetectRIPRelative(t *testing.T) {
	// LEA rax, [rip+0x1234] = 48 8D 05 34 12 00 00
	code := []byte{0x48, 0x8D, 0x05, 0x34, 0x12, 0x00, 0x00}
	relocs, err := detectRIPRelative(code, 7)
	require.NoError(t, err)
	require.Len(t, relocs, 1)
	require.Equal(t, 0, relocs[0].instrOffset)
	require.Equal(t, 3, relocs[0].dispOffset)
	require.Equal(t, 7, relocs[0].instrLen)
	require.Equal(t, int32(0x1234), relocs[0].origDisp)
}

func TestDetectRIPRelativeNone(t *testing.T) {
	code := []byte{0x48, 0x83, 0xEC, 0x28}
	relocs, err := detectRIPRelative(code, 4)
	require.NoError(t, err)
	require.Empty(t, relocs)
}

func TestDetectRIPRelativeMultiple(t *testing.T) {
	code := []byte{
		0x48, 0x8D, 0x05, 0x10, 0x00, 0x00, 0x00, // LEA rax, [rip+0x10]
		0x48, 0x8B, 0x05, 0x20, 0x00, 0x00, 0x00, // MOV rax, [rip+0x20]
	}
	relocs, err := detectRIPRelative(code, 14)
	require.NoError(t, err)
	require.Len(t, relocs, 2)
	require.Equal(t, int32(0x10), relocs[0].origDisp)
	require.Equal(t, int32(0x20), relocs[1].origDisp)
}
