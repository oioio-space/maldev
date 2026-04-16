package bridge

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/oioio-space/maldev/c2/transport/namedpipe"
)

// DialPipe connects to a named pipe.
func DialPipe(name string, timeout time.Duration) (io.ReadWriteCloser, error) {
	p := namedpipe.New(name, timeout)
	if err := p.Connect(context.Background()); err != nil {
		return nil, fmt.Errorf("dial pipe %s: %w", name, err)
	}
	return p, nil
}

// DialTCP connects to a TCP address.
func DialTCP(addr string, timeout time.Duration) (io.ReadWriteCloser, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("dial tcp %s: %w", addr, err)
	}
	return conn, nil
}
