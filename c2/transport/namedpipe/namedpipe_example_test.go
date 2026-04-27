package namedpipe_test

import (
	"context"
	"fmt"
	"time"

	"github.com/oioio-space/maldev/c2/transport/namedpipe"
)

// New builds a Pipe transport for a named-pipe address.
// `\\.\pipe\name` for the local machine, `\\HOSTNAME\pipe\name` for
// remote.
func ExampleNew() {
	p := namedpipe.New(`\\.\pipe\maldev`, 5*time.Second)
	if err := p.Connect(context.Background()); err != nil {
		fmt.Println("connect:", err)
		return
	}
	defer p.Close()
	_, _ = p.Write([]byte("ping"))
}
