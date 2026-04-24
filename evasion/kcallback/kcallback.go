package kcallback

import "errors"

// ErrNoKernelReader is returned when an operation requires reading
// kernel memory and the injected KernelReader is nil or the default
// NullKernelReader. Callers must plug in a driver-backed reader
// (RTCore64, GDRV, custom driver) before the enumeration APIs can
// actually produce results.
var ErrNoKernelReader = errors.New("kcallback: no KernelReader available (plug in a driver-backed primitive)")

// ErrReadOnly is returned when a caller asks for a write-capable
// operation (e.g. Remove) but the injected reader only implements
// KernelReader, not KernelReadWriter.
var ErrReadOnly = errors.New("kcallback: reader is not KernelReadWriter (removal unsupported)")

// ErrNtoskrnlNotFound is returned when NtQuerySystemInformation's
// SystemModuleInformation walk cannot locate ntoskrnl.exe — should
// never happen on a booted Windows host.
var ErrNtoskrnlNotFound = errors.New("kcallback: ntoskrnl.exe not in SystemModuleInformation")

// ErrOffsetUnknown is returned when the caller did not supply an
// offset for the target array on the current ntoskrnl build. The
// package does NOT ship a built-in offset database because offsets
// shift with every cumulative update; callers derive offsets from
// PDB dumps and plug them in via OffsetTable.
var ErrOffsetUnknown = errors.New("kcallback: no offset registered for current ntoskrnl build")

// Kind identifies which callback array a Callback belongs to.
type Kind int

const (
	KindCreateProcess Kind = iota + 1
	KindCreateThread
	KindLoadImage
)

// String renders the Kind for diagnostics.
func (k Kind) String() string {
	switch k {
	case KindCreateProcess:
		return "PspCreateProcessNotifyRoutine"
	case KindCreateThread:
		return "PspCreateThreadNotifyRoutine"
	case KindLoadImage:
		return "PspLoadImageNotifyRoutine"
	default:
		return "kcallback.Kind(unknown)"
	}
}

// Callback describes one entry in a kernel callback array.
type Callback struct {
	Kind     Kind    // which array
	Index    int     // slot in the array
	Address  uintptr // kernel VA of the callback function (masked PEX_CALLBACK_ROUTINE_BLOCK)
	Module   string  // resolved driver name (best effort)
	Enabled  bool    // false when the low bit is 0 (indicates disabled slot)
}

// OffsetTable maps an ntoskrnl build number to the array offsets
// relative to ntoskrnl's image base. Callers populate this from
// offline PDB dumps and hand it to Enumerate. Omitting a field
// skips enumeration of that particular array.
//
// Build is the low dword of the OS build as returned by RtlGetVersion
// (e.g. 19045, 22631). Revision granularity is not tracked — most
// symbol offsets are stable across revisions within a build.
type OffsetTable struct {
	Build                   uint32
	CreateProcessRoutineRVA uint32
	CreateThreadRoutineRVA  uint32
	LoadImageRoutineRVA     uint32
	// ArrayLen is the maximum number of callback slots per array
	// (typically 64 on Win10, 96+ on Win11). Zero defaults to 64.
	ArrayLen int
}

// KernelReader abstracts "read N bytes from kernel VA addr". Any driver
// primitive that exposes this contract can plug in. The default
// NullKernelReader always returns ErrNoKernelReader so callers fail
// loudly on misconfiguration.
type KernelReader interface {
	ReadKernel(addr uintptr, buf []byte) (int, error)
}

// KernelReadWriter extends KernelReader with a write primitive. Used
// by the experimental Remove paths.
type KernelReadWriter interface {
	KernelReader
	WriteKernel(addr uintptr, data []byte) (int, error)
}

// NullKernelReader is the default injection target — every call
// returns ErrNoKernelReader. Used as a placeholder so callers can
// construct fully-wired pipelines and only decide on the concrete
// driver primitive at deployment time.
type NullKernelReader struct{}

// ReadKernel always returns ErrNoKernelReader.
func (NullKernelReader) ReadKernel(_ uintptr, _ []byte) (int, error) {
	return 0, ErrNoKernelReader
}
