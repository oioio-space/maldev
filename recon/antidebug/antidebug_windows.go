//go:build windows

// Package antidebug provides debugger detection techniques.
package antidebug

import "github.com/oioio-space/maldev/win/api"

// IsDebuggerPresent returns true if the process is being debugged.
func IsDebuggerPresent() bool {
	r, _, _ := api.ProcIsDebuggerPresent.Call()
	return r != 0
}
