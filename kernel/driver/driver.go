package driver

import "errors"

// ErrNotImplemented is returned by primitive operations that the
// concrete driver does not yet expose. Sub-package scaffolds use this
// while the IOCTL layer is still under research.
var ErrNotImplemented = errors.New("kernel/driver: primitive not implemented")

// ErrNotLoaded is returned when a Reader/Writer call lands before the
// driver service has been installed and started.
var ErrNotLoaded = errors.New("kernel/driver: driver not loaded")

// ErrPrivilegeRequired is returned by Install paths when the calling
// thread lacks SeLoadDriverPrivilege (admin token typically required
// to register and start a kernel driver service).
var ErrPrivilegeRequired = errors.New("kernel/driver: SeLoadDriverPrivilege required")

// Reader exposes "read N bytes from a kernel virtual address". It is
// shape-compatible with evasion/kcallback.KernelReader so concrete
// drivers can plug into both kernel/driver consumers and kcallback.
type Reader interface {
	ReadKernel(addr uintptr, buf []byte) (int, error)
}

// ReadWriter extends Reader with a write primitive.
type ReadWriter interface {
	Reader
	WriteKernel(addr uintptr, data []byte) (int, error)
}

// Lifecycle abstracts the install / start / stop / uninstall sequence
// every BYOVD primitive shares. Concrete drivers implement this
// alongside Reader / ReadWriter so tooling can manage their lifetime
// uniformly without knowing which signed driver is in play.
type Lifecycle interface {
	// Install drops the driver bytes to disk, registers the service,
	// and starts it. Idempotent: calling Install on an already-loaded
	// driver returns nil.
	Install() error

	// Uninstall stops the service, deletes its registration, and
	// removes the driver file from disk. Best-effort: errors at each
	// step are logged but the chain continues so partial state is
	// always cleaned up.
	Uninstall() error

	// Loaded reports whether the driver service is currently running.
	Loaded() bool
}
