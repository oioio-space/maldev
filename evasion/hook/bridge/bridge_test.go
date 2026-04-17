package bridge

import (
	"bytes"
	"io"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// skipIfNonWindowsController skips tests that exercise the real (Windows-only)
// Controller implementation. The non-Windows stub returns no-ops so the
// pipe-based round-trip assertions can never succeed.
func skipIfNonWindowsController(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Controller round-trip needs the Windows implementation (controller_stub on other OSes is no-op)")
	}
}

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
	skipIfNonWindowsController(t)
	sr, cw := io.Pipe()
	cr, sw := io.Pipe()

	ctrl := Connect(&readWriteCloser{Reader: cr, Writer: cw, Closer: cw})
	lis := NewListener(&readWriteCloser{Reader: sr, Writer: sw, Closer: sw})

	var receivedTag string
	var receivedData []byte
	lis.OnCall(func(c Call) Decision {
		receivedTag = c.Tag
		receivedData = c.Data
		return Block
	})

	var logMsg string
	lis.OnLog(func(msg string) { logMsg = msg })

	go ctrl.Serve()
	go lis.Serve()

	ctrl.Log("test message")
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, "test message", logMsg)

	decision := ctrl.Ask("delete_file", []byte(`C:\secret.txt`))
	require.Equal(t, Block, decision)
	require.Equal(t, "delete_file", receivedTag)
	require.Equal(t, []byte(`C:\secret.txt`), receivedData)

	require.NoError(t, lis.Close())
}

func TestControllerHeartbeat(t *testing.T) {
	skipIfNonWindowsController(t)
	sr, cw := io.Pipe()
	cr, sw := io.Pipe()

	ctrl := Connect(&readWriteCloser{Reader: cr, Writer: cw, Closer: cw})
	lis := NewListener(&readWriteCloser{Reader: sr, Writer: sw, Closer: sw})
	go ctrl.Serve()
	go lis.Serve()

	require.NoError(t, ctrl.Heartbeat())
	require.NoError(t, lis.Close())
}

func TestControllerExfil(t *testing.T) {
	skipIfNonWindowsController(t)
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
	go ctrl.Serve()
	go lis.Serve()

	ctrl.Exfil("lsass", []byte("dumpdata"))
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, "lsass", gotTag)
	require.Equal(t, []byte("dumpdata"), gotData)

	require.NoError(t, lis.Close())
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

func TestRPCCall(t *testing.T) {
	skipIfNonWindowsController(t)
	sr, cw := io.Pipe()
	cr, sw := io.Pipe()

	ctrl := Connect(&readWriteCloser{Reader: cr, Writer: cw, Closer: cw})
	lis := NewListener(&readWriteCloser{Reader: sr, Writer: sw, Closer: sw})

	ctrl.Register("echo", func(data []byte) ([]byte, error) {
		return append([]byte("ECHO:"), data...), nil
	})

	ctrl.Register("add", func(data []byte) ([]byte, error) {
		a := int(data[0])
		b := int(data[1])
		return []byte{byte(a + b)}, nil
	})

	go ctrl.Serve()
	go lis.Serve()

	resp, err := lis.Call("echo", []byte("hello"))
	require.NoError(t, err)
	require.Equal(t, []byte("ECHO:hello"), resp)

	resp, err = lis.Call("add", []byte{3, 7})
	require.NoError(t, err)
	require.Equal(t, []byte{10}, resp)

	require.NoError(t, lis.Close())
}

func TestRPCUnknownCommand(t *testing.T) {
	skipIfNonWindowsController(t)
	sr, cw := io.Pipe()
	cr, sw := io.Pipe()

	ctrl := Connect(&readWriteCloser{Reader: cr, Writer: cw, Closer: cw})
	lis := NewListener(&readWriteCloser{Reader: sr, Writer: sw, Closer: sw})

	go ctrl.Serve()
	go lis.Serve()

	_, err := lis.Call("nonexistent", nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown command")

	require.NoError(t, lis.Close())
}

func TestRPCAndHookConcurrent(t *testing.T) {
	skipIfNonWindowsController(t)
	sr, cw := io.Pipe()
	cr, sw := io.Pipe()

	ctrl := Connect(&readWriteCloser{Reader: cr, Writer: cw, Closer: cw})
	lis := NewListener(&readWriteCloser{Reader: sr, Writer: sw, Closer: sw})

	ctrl.Register("ping", func(_ []byte) ([]byte, error) {
		return []byte("pong"), nil
	})

	var hookTag string
	lis.OnCall(func(c Call) Decision {
		hookTag = c.Tag
		return Block
	})

	go ctrl.Serve()
	go lis.Serve()

	// RPC call (implant → handler)
	resp, err := lis.Call("ping", nil)
	require.NoError(t, err)
	require.Equal(t, []byte("pong"), resp)

	// Hook call (handler → implant) — concurrent with RPC
	decision := ctrl.Ask("delete_file", []byte("test"))
	require.Equal(t, Block, decision)
	require.Equal(t, "delete_file", hookTag)

	require.NoError(t, lis.Close())
}

func TestRPCReadMemory(t *testing.T) {
	skipIfNonWindowsController(t)
	sr, cw := io.Pipe()
	cr, sw := io.Pipe()

	ctrl := Connect(&readWriteCloser{Reader: cr, Writer: cw, Closer: cw})
	lis := NewListener(&readWriteCloser{Reader: sr, Writer: sw, Closer: sw})

	ctrl.Register("read_memory", func(data []byte) ([]byte, error) {
		return []byte("MEMDATA"), nil
	})

	go ctrl.Serve()
	go lis.Serve()

	resp, err := lis.ReadMemory(0x1234, 256)
	require.NoError(t, err)
	require.Equal(t, []byte("MEMDATA"), resp)

	require.NoError(t, lis.Close())
}

func TestRPCTyped(t *testing.T) {
	skipIfNonWindowsController(t)
	sr, cw := io.Pipe()
	cr, sw := io.Pipe()

	ctrl := Connect(&readWriteCloser{Reader: cr, Writer: cw, Closer: cw})
	lis := NewListener(&readWriteCloser{Reader: sr, Writer: sw, Closer: sw})

	type SearchResult struct {
		Matches []string
		Count   int
	}

	rpcHandler := NewRPCHandler(ctrl)
	rpcHandler.Handle("search", func(query string) (SearchResult, error) {
		return SearchResult{
			Matches: []string{"file1_" + query, "file2_" + query},
			Count:   2,
		}, nil
	})

	go ctrl.Serve()
	go lis.Serve()

	rpc := NewRPC(lis)
	var result SearchResult
	err := rpc.Call("search", "secret", &result)
	require.NoError(t, err)
	require.Equal(t, 2, result.Count)
	require.Equal(t, []string{"file1_secret", "file2_secret"}, result.Matches)

	require.NoError(t, lis.Close())
}

func TestRPCNoArgs(t *testing.T) {
	skipIfNonWindowsController(t)
	sr, cw := io.Pipe()
	cr, sw := io.Pipe()

	ctrl := Connect(&readWriteCloser{Reader: cr, Writer: cw, Closer: cw})
	lis := NewListener(&readWriteCloser{Reader: sr, Writer: sw, Closer: sw})

	rpcHandler := NewRPCHandler(ctrl)
	rpcHandler.Handle("ping", func() (interface{}, error) {
		return "pong", nil
	})

	go ctrl.Serve()
	go lis.Serve()

	rpc := NewRPC(lis)
	var result string
	err := rpc.Call("ping", nil, &result)
	require.NoError(t, err)
	require.Equal(t, "pong", result)

	require.NoError(t, lis.Close())
}

func TestRPCFireAndForget(t *testing.T) {
	skipIfNonWindowsController(t)
	sr, cw := io.Pipe()
	cr, sw := io.Pipe()

	ctrl := Connect(&readWriteCloser{Reader: cr, Writer: cw, Closer: cw})
	lis := NewListener(&readWriteCloser{Reader: sr, Writer: sw, Closer: sw})

	var received string
	rpcHandler := NewRPCHandler(ctrl)
	rpcHandler.Handle("log_event", func(msg string) (string, error) {
		received = msg
		return "", nil
	})

	go ctrl.Serve()
	go lis.Serve()

	rpc := NewRPC(lis)
	err := rpc.Call("log_event", "something happened", nil)
	require.NoError(t, err)
	require.Equal(t, "something happened", received)

	require.NoError(t, lis.Close())
}

type readWriteCloser struct {
	io.Reader
	io.Writer
	io.Closer
}
