//go:build windows

package bof

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBeaconOutputCapture(t *testing.T) {
	out := newBeaconOutput()
	out.printf("hello %s", "world")
	require.Equal(t, "hello world", out.String())
}

func TestBeaconOutputBytes(t *testing.T) {
	out := newBeaconOutput()
	out.write([]byte{0x41, 0x42})
	require.Equal(t, []byte{0x41, 0x42}, out.Bytes())
}

func TestBeaconOutputAppends(t *testing.T) {
	out := newBeaconOutput()
	out.write([]byte("foo"))
	out.write([]byte("bar"))
	require.Equal(t, "foobar", out.String())
}

func TestBeaconOutputBytesIsolated(t *testing.T) {
	// Bytes() must return a copy — mutations must not affect the internal buffer.
	out := newBeaconOutput()
	out.write([]byte{0x01, 0x02})
	got := out.Bytes()
	got[0] = 0xFF
	require.Equal(t, []byte{0x01, 0x02}, out.Bytes())
}

func TestArgsPackInt(t *testing.T) {
	args := NewArgs()
	args.AddInt(42)
	packed := args.Pack()
	require.Len(t, packed, 4)
	v := binary.LittleEndian.Uint32(packed)
	require.Equal(t, uint32(42), v)
}

func TestArgsPackIntNegative(t *testing.T) {
	args := NewArgs()
	args.AddInt(-1)
	packed := args.Pack()
	require.Len(t, packed, 4)
	// -1 as two's complement uint32 is 0xFFFFFFFF.
	require.Equal(t, uint32(0xFFFFFFFF), binary.LittleEndian.Uint32(packed))
}

func TestArgsPackShort(t *testing.T) {
	args := NewArgs()
	args.AddShort(7)
	packed := args.Pack()
	require.Len(t, packed, 2)
	require.Equal(t, uint16(7), binary.LittleEndian.Uint16(packed))
}

func TestArgsPackString(t *testing.T) {
	args := NewArgs()
	args.AddString("test")
	packed := args.Pack()
	// 4-byte length prefix + "test" + null terminator = 9 bytes total.
	require.Len(t, packed, 4+5)
	length := binary.LittleEndian.Uint32(packed[:4])
	require.Equal(t, uint32(5), length)
	require.Equal(t, "test", string(packed[4:8]))
	require.Equal(t, byte(0), packed[8])
}

func TestArgsPackStringEmpty(t *testing.T) {
	args := NewArgs()
	args.AddString("")
	packed := args.Pack()
	// Empty string: length = 1 (just null), 4-byte prefix + null.
	require.Len(t, packed, 5)
	require.Equal(t, uint32(1), binary.LittleEndian.Uint32(packed[:4]))
	require.Equal(t, byte(0), packed[4])
}

func TestArgsPackBytes(t *testing.T) {
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	args := NewArgs()
	args.AddBytes(data)
	packed := args.Pack()
	// 4-byte length prefix + 4 data bytes = 8 bytes total.
	require.Len(t, packed, 8)
	length := binary.LittleEndian.Uint32(packed[:4])
	require.Equal(t, uint32(4), length)
	require.Equal(t, data, packed[4:])
}

func TestArgsPackBytesEmpty(t *testing.T) {
	args := NewArgs()
	args.AddBytes([]byte{})
	packed := args.Pack()
	require.Len(t, packed, 4)
	require.Equal(t, uint32(0), binary.LittleEndian.Uint32(packed[:4]))
}

func TestArgsPackMultiple(t *testing.T) {
	args := NewArgs()
	args.AddInt(1)
	args.AddShort(2)
	args.AddString("hi")
	packed := args.Pack()
	require.NotEmpty(t, packed)
	// 4 (int) + 2 (short) + 4 (len prefix) + 3 ("hi\0") = 13 bytes.
	require.Len(t, packed, 13)
}

func TestArgsPackIsolated(t *testing.T) {
	// Pack() must return a copy — mutations must not affect subsequent calls.
	args := NewArgs()
	args.AddInt(99)
	first := args.Pack()
	first[0] = 0xFF
	second := args.Pack()
	require.Equal(t, uint32(99), binary.LittleEndian.Uint32(second))
}
