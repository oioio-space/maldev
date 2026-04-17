// Command memscan-server exposes a minimal HTTP/JSON inspection API
// (ReadProcessMemory, EnumProcessModules, export lookup) on port 50300 so
// that host-side test orchestrators can verify byte patterns inside a
// running target process. It replaces the old x64dbg+MCP setup for the
// static verification matrix (75 tests) — execution verification stays
// on canary scans and the Kali Meterpreter matrix.
//
// Runs on Windows only. On any other platform the server refuses to start.
//
// Usage:
//
//	memscan-server [--addr 0.0.0.0:50300]
package main

import (
	"flag"
	"fmt"
	"os"
)

const defaultAddr = "0.0.0.0:50300"

func main() {
	addr := flag.String("addr", defaultAddr, "listen address")
	flag.Parse()
	if err := run(*addr); err != nil {
		fmt.Fprintf(os.Stderr, "memscan-server: %v\n", err)
		os.Exit(1)
	}
}
