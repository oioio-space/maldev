package bridge

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("hello bridge")
	require.NoError(t, writeFrame(&buf, msgLog, payload))
	msgType, data, err := readFrame(&buf)
	require.NoError(t, err)
	require.Equal(t, msgLog, msgType)
	require.Equal(t, payload, data)
}

func TestFrameEmpty(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, writeFrame(&buf, msgHeartbeat, nil))
	msgType, data, err := readFrame(&buf)
	require.NoError(t, err)
	require.Equal(t, msgHeartbeat, msgType)
	require.Empty(t, data)
}

func TestArgsRoundTrip(t *testing.T) {
	var args [18]uintptr
	args[0] = 0x1234
	args[3] = 0xDEAD
	args[17] = 0xFFFF
	encoded := encodeArgs(args)
	decoded := decodeArgs(encoded)
	require.Equal(t, args, decoded)
}

func TestArgBlockNonZero(t *testing.T) {
	ab := &ArgBlock{Args: [18]uintptr{1, 0, 3, 0, 5}}
	require.Equal(t, 3, ab.NonZeroCount())
	require.Equal(t, []int{0, 2, 4}, ab.NonZeroArgs())
}

func TestArgBlockInt(t *testing.T) {
	ab := &ArgBlock{Args: [18]uintptr{42}}
	require.Equal(t, int64(42), ab.Int(0))
	require.Equal(t, int64(0), ab.Int(99))
}

func TestDecisionConstants(t *testing.T) {
	require.Equal(t, Decision(0), Allow)
	require.Equal(t, Decision(1), Block)
	require.Equal(t, Decision(2), Modify)
}

func TestSplitTagData(t *testing.T) {
	tag, data := splitTagData([]byte("mytag\x00somedata"))
	require.Equal(t, "mytag", tag)
	require.Equal(t, []byte("somedata"), data)
}

func TestSplitTagDataNoNull(t *testing.T) {
	tag, data := splitTagData([]byte("justtext"))
	require.Equal(t, "justtext", tag)
	require.Nil(t, data)
}
