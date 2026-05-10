//go:build !windows

// Package main on non-Windows platforms is a stub. The asmtrace
// harness is Windows-only — it relies on AddVectoredExceptionHandler
// which has no portable Linux/macOS counterpart that yields the
// same register-state diagnostic without cgo + sigaction.
//
// Linux asm-primitive runtime tests should use direct syscall-based
// shellcode (e.g. exit_group) which doesn't fault silently — when
// our test fixtures crash on Linux, gdb is the supervised debug
// path. This stub exists only so `go build ./...` succeeds on the
// development host.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "asmtrace: Windows-only — see package doc for the operational rationale")
	os.Exit(2)
}
