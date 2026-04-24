package lsassdump

import "errors"

// ErrLSASSNotFound is returned when the NtGetNextProcess walk finishes
// without locating an image named "lsass.exe". In practice this never
// happens on a booted Windows host — always treat it as a bug.
var ErrLSASSNotFound = errors.New("lsassdump: lsass.exe not found")

// ErrOpenDenied wraps any ACCESS_DENIED returned by the NtOpenProcess
// equivalent. Usually means the caller is not an admin or Protected
// Process Light is enforced (Credential Guard, HVCI, RunAsPPL=1).
var ErrOpenDenied = errors.New("lsassdump: access denied opening lsass.exe (admin? PPL?)")

// ErrPPL is returned when lsass.exe is running as a Protected Process
// Light and PROCESS_VM_READ is refused even to SYSTEM. Bypassing PPL
// requires a separate primitive (signed-driver unprotect, mimidrv,
// or a kernel-write chain) that is out of scope for this package.
var ErrPPL = errors.New("lsassdump: lsass.exe is PPL-protected; VM_READ denied")

// Stats describes what Dump emitted. Useful in tests and for callers
// that want to log post-dump telemetry.
type Stats struct {
	Regions     int    // number of MEMORY64_LIST entries written
	Bytes       uint64 // total bytes of process memory captured
	ModuleCount int    // entries in the MODULE_LIST stream
	ThreadCount int    // entries in the THREAD_LIST stream
}
