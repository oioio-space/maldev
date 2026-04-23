//go:build windows

package sleepmask

// Region describes a memory region to encrypt during sleep, within the
// current process. For cross-process masking see RemoteRegion.
type Region struct {
	Addr uintptr
	Size uintptr
}
