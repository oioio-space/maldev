//go:build !windows

package lsassdump

import (
	"errors"
	"io"

	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

var errUnsupported = errors.New("lsassdump: requires Windows")

// OpenLSASS is a non-Windows stub. See lsassdump_windows.go for the
// real signature contract.
func OpenLSASS(_ *wsyscall.Caller) (uintptr, error) {
	return 0, errUnsupported
}

// CloseLSASS is a non-Windows stub.
func CloseLSASS(_ uintptr) error { return errUnsupported }

// LsassPID is a non-Windows stub.
func LsassPID(_ *wsyscall.Caller) (uint32, error) {
	return 0, errUnsupported
}

// Dump is a non-Windows stub.
func Dump(_ uintptr, _ io.Writer, _ *wsyscall.Caller) (Stats, error) {
	return Stats{}, errUnsupported
}

// DumpToFile is a non-Windows stub.
func DumpToFile(_ string, _ *wsyscall.Caller) (Stats, error) {
	return Stats{}, errUnsupported
}
