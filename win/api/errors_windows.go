//go:build windows

package api

import "fmt"

// ErrNotSupported is returned when a feature is unavailable on the target Windows version.
var ErrNotSupported = fmt.Errorf("not supported on this Windows version")

// NTSTATUSError wraps an NTSTATUS code as a Go error.
type NTSTATUSError uint32

func (e NTSTATUSError) Error() string { return fmt.Sprintf("NTSTATUS 0x%08X", uint32(e)) }

// IsNTSuccess returns true if the NTSTATUS indicates success (0x00000000).
func IsNTSuccess(status uintptr) bool { return status == 0 }
