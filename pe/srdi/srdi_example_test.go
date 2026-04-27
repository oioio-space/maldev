package srdi_test

import (
	"fmt"
	"os"

	"github.com/oioio-space/maldev/pe/srdi"
)

// ConvertFile turns a native EXE on disk into Donut-wrapped
// position-independent shellcode ready to feed an injector.
func ExampleConvertFile() {
	cfg := srdi.DefaultConfig()
	cfg.Type = srdi.ModuleEXE
	cfg.Arch = srdi.ArchX64

	sc, err := srdi.ConvertFile("payload.exe", cfg)
	if err != nil {
		return
	}
	fmt.Printf("shellcode %d bytes\n", len(sc))
}

// ConvertBytes accepts a PE in memory — useful for downloaded /
// decrypted payloads that never touch disk. The DLL variant
// requires Config.Method to name the export to invoke.
func ExampleConvertBytes() {
	peData, err := os.ReadFile("payload.dll")
	if err != nil {
		return
	}
	cfg := &srdi.Config{
		Arch:   srdi.ArchX64,
		Type:   srdi.ModuleDLL,
		Method: "Run",
		Bypass: 3,
	}
	sc, err := srdi.ConvertBytes(peData, cfg)
	if err != nil {
		return
	}
	fmt.Printf("shellcode %d bytes\n", len(sc))
}
