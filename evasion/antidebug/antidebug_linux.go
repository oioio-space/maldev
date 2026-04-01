//go:build linux

// Package antidebug provides debugger detection techniques.
package antidebug

import (
	"fmt"
	"os"
	"strings"
)

// IsDebuggerPresent checks /proc/self/status for TracerPid to detect a debugger.
func IsDebuggerPresent() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "TracerPid:") {
			var pid int
			if _, err := fmt.Sscanf(line, "TracerPid:\t%d", &pid); err == nil {
				return pid != 0
			}
		}
	}
	return false
}
