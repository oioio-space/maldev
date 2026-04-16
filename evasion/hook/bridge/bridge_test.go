package bridge

import (
	"bytes"
	"io"
	"testing"
	"time"

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

func TestControllerListenerRoundTrip(t *testing.T) {
	sr, cw := io.Pipe() // server reads what controller writes
	cr, sw := io.Pipe() // controller reads what server writes

	ctrlConn := readWriteCloser{Reader: cr, Writer: cw, Closer: cw}
	lisConn := readWriteCloser{Reader: sr, Writer: sw, Closer: sw}

	ctrl := Connect(&ctrlConn)
	lis := NewListener(&lisConn)

	var receivedTag string
	var receivedData []byte
	lis.OnCall(func(c Call) Decision {
		receivedTag = c.Tag
		receivedData = c.Data
		return Block
	})

	var logMsg string
	lis.OnLog(func(msg string) { logMsg = msg })

	go lis.Serve()

	ctrl.Log("test message")
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, "test message", logMsg)

	decision := ctrl.Ask("delete_file", []byte(`C:\secret.txt`))
	require.Equal(t, Block, decision)
	require.Equal(t, "delete_file", receivedTag)
	require.Equal(t, []byte(`C:\secret.txt`), receivedData)

	require.NoError(t, ctrl.Close())
}

func TestControllerHeartbeat(t *testing.T) {
	sr, cw := io.Pipe()
	cr, sw := io.Pipe()

	ctrl := Connect(&readWriteCloser{Reader: cr, Writer: cw, Closer: cw})
	lis := NewListener(&readWriteCloser{Reader: sr, Writer: sw, Closer: sw})
	go lis.Serve()

	require.NoError(t, ctrl.Heartbeat())
	require.NoError(t, ctrl.Close())
}

func TestControllerExfil(t *testing.T) {
	sr, cw := io.Pipe()
	cr, sw := io.Pipe()

	ctrl := Connect(&readWriteCloser{Reader: cr, Writer: cw, Closer: cw})
	lis := NewListener(&readWriteCloser{Reader: sr, Writer: sw, Closer: sw})

	var gotTag string
	var gotData []byte
	lis.OnExfil(func(tag string, data []byte) {
		gotTag = tag
		gotData = data
	})
	go lis.Serve()

	ctrl.Exfil("lsass", []byte("dumpdata"))
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, "lsass", gotTag)
	require.Equal(t, []byte("dumpdata"), gotData)

	require.NoError(t, ctrl.Close())
}

func TestStandalone(t *testing.T) {
	ctrl := Standalone()
	// All methods must be no-ops and not panic.
	ctrl.Log("ignored %s", "msg")
	ctrl.Exfil("tag", []byte("data"))
	require.Equal(t, Allow, ctrl.Ask("tag", []byte("data")))
	require.NoError(t, ctrl.Heartbeat())
	require.NoError(t, ctrl.Close())
	require.NotNil(t, ctrl.Args())
}

type readWriteCloser struct {
	io.Reader
	io.Writer
	io.Closer
}
