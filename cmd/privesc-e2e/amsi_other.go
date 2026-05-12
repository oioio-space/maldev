//go:build !windows

package main

// patchAMSI is a no-op outside Windows -- AMSI doesn't exist there.
// The orchestrator is Windows-targeted; this stub keeps go build
// happy on the host when cross-compiling host helpers.
func patchAMSI() error { return nil }
