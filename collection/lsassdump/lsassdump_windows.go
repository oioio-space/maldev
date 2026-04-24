//go:build windows

package lsassdump

import (
	"errors"
	"io"

	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// errNotImplemented is a scaffold sentinel — each real call site replaces
// it with its actual implementation in C1.3 of the v0.15.0 plan.
var errNotImplemented = errors.New("lsassdump: not implemented yet")

// OpenLSASS walks the running-process list via NtGetNextProcess (no
// PID enumeration, no path resolution via OpenProcess) until it finds
// lsass.exe, opens it with PROCESS_QUERY_LIMITED_INFORMATION |
// PROCESS_VM_READ, and returns the handle. Caller (optional) routes the
// underlying syscalls through a user-chosen wsyscall strategy.
//
// Callers MUST pair every successful OpenLSASS with a CloseLSASS to avoid
// leaking a process handle.
func OpenLSASS(caller *wsyscall.Caller) (uintptr, error) {
	_ = caller
	return 0, errNotImplemented
}

// CloseLSASS closes the handle returned by OpenLSASS.
func CloseLSASS(h uintptr) error {
	_ = h
	return errNotImplemented
}

// Dump reads lsass.exe's memory via NtReadVirtualMemory and writes a
// MINIDUMP stream (MINIDUMP_TYPE 0x61B: FullMemory + HandleData +
// ThreadInfo + TokenInformation) to w. The returned Stats summarises
// what landed in the blob. Caller (optional) routes the memory reads
// through the wsyscall strategy of the caller's choice.
func Dump(h uintptr, w io.Writer, caller *wsyscall.Caller) (Stats, error) {
	_ = h
	_ = w
	_ = caller
	return Stats{}, errNotImplemented
}

// DumpToFile is a convenience: open lsass, Dump into path (0o600), close
// the handle on any outcome. path is written with O_CREATE|O_TRUNC|O_WRONLY
// and synced to disk before the function returns.
func DumpToFile(path string, caller *wsyscall.Caller) (Stats, error) {
	_ = path
	_ = caller
	return Stats{}, errNotImplemented
}
