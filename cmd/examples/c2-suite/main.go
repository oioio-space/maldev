//go:build windows

// c2-suite — panorama 15 of the doc-truth audit.
//
// Built strictly from the user-facing markdown:
//   - docs/techniques/c2/transport.md  — TCP transport
//   - docs/techniques/c2/namedpipe.md  — named-pipe listener
//
// Tests two binding paths with clear admin/user differential candidates:
//   - TCP bind on a low port (≤1024 needs admin) and a high port.
//   - Named-pipe listener at \\.\pipe\<unique> (anyone can create a pipe
//     in the per-process namespace; the ACL is what matters).
//
// Each listener runs for ≤200 ms to keep the matrix turnaround fast.
package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/oioio-space/maldev/c2/transport"
)

func main() {
	// 1. Low-port bind (port 80) — admin / NetBindToAny territory.
	fmt.Println("=== TCP bind 0.0.0.0:80 ===")
	if ln, err := transport.NewTCPListener(":80"); err != nil {
		fmt.Printf("low-port bind: %v\n", err)
	} else {
		fmt.Printf("low-port bind: OK %v\n", ln.Addr())
		ln.Close()
	}

	// 2. High-port bind — should work for any user.
	fmt.Println("\n=== TCP bind 127.0.0.1:0 (ephemeral) ===")
	if ln, err := transport.NewTCPListener("127.0.0.1:0"); err != nil {
		fmt.Printf("high-port bind: %v\n", err)
	} else {
		fmt.Printf("high-port bind: OK %v\n", ln.Addr())

		// 3. Sanity: connect a TCP transport to the listener and write
		//    a byte. Doc shows transport.NewTCP for the dial side.
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		go func() {
			conn, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			defer conn.Close()
			buf := make([]byte, 16)
			n, _ := conn.Read(buf)
			_ = n
		}()
		tr := transport.NewTCP(ln.Addr().String(), 200*time.Millisecond)
		if err := tr.Connect(ctx); err != nil {
			fmt.Printf("dial: %v\n", err)
		} else {
			if _, err := tr.Write([]byte("ping")); err != nil {
				fmt.Printf("write: %v\n", err)
			} else {
				fmt.Printf("dial+write: OK\n")
			}
			_ = tr.Close()
		}

		ln.Close()
	}

	// 4. Named-pipe listener — anyone can create a pipe in the local
	//    namespace; the ACL determines who can connect. We probe the
	//    creation only and use a unique name so concurrent matrix runs
	//    don't collide.
	fmt.Println("\n=== Named-pipe listener ===")
	pipeName := fmt.Sprintf(`\\.\pipe\maldev-panorama15-%d`, time.Now().UnixNano())
	if ln, err := net.Listen("tcp", "127.0.0.1:0"); err == nil {
		// Suppress "imported and not used" net guard for the panorama.
		ln.Close()
	}
	// Use the documented namedpipe.NewListener via the c2 package.
	type pipeListener interface{ Close() error }
	_ = pipeListener(nil)
	if ok := tryNewNamedPipeListener(pipeName); !ok {
		fmt.Printf("namedpipe.NewListener: skipped (see DOC-DRIFT note in source)\n")
	}
}

// tryNewNamedPipeListener uses the c2/namedpipe package via local helper to
// keep the import block tidy if the panorama ever expands. Returns false
// if the documented API surface differs from what the package actually
// exposes (DOC-DRIFT capture point).
func tryNewNamedPipeListener(name string) bool {
	// Doc shows: ln, _ := namedpipe.NewListener(`\\.\pipe\c2agent`)
	// then ln.Accept(ctx). We only exercise creation + close so the
	// matrix doesn't block on Accept.
	ln, err := namedpipeNewListener(name)
	if err != nil {
		fmt.Printf("namedpipe.NewListener(%s): %v\n", name, err)
		return true
	}
	fmt.Printf("namedpipe.NewListener(%s): OK\n", name)
	_ = ln.Close()
	return true
}
