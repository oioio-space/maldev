// Package srdi provides PE/DLL/EXE-to-shellcode conversion using the Donut
// framework (github.com/Binject/go-donut).
//
// Supported input formats:
//   - Native EXE (ModuleEXE)
//   - Native DLL (ModuleDLL) — call specific export via Config.Method
//   - .NET EXE (ModuleNetEXE)
//   - .NET DLL (ModuleNetDLL) — specify Config.Class and Config.Method
//   - VBScript (ModuleVBS)
//   - JScript (ModuleJS)
//   - XSL (ModuleXSL)
//
// Usage:
//
//	// Convert a native DLL to shellcode
//	cfg := srdi.DefaultConfig()
//	cfg.Type = srdi.ModuleDLL
//	cfg.Method = "MyExport"
//	shellcode, err := srdi.ConvertFile("payload.dll", cfg)
//
//	// Convert raw bytes (e.g., downloaded PE)
//	cfg := &srdi.Config{Arch: srdi.ArchX64, Type: srdi.ModuleEXE, Bypass: 3}
//	shellcode, err := srdi.ConvertBytes(peData, cfg)
//
// Technique: PE-to-Shellcode Conversion (Donut)
// MITRE ATT&CK: T1055.001 (Process Injection: DLL Injection)
// Platform: Cross-platform generation, Windows x86/x64 shellcode output
// Detection: Medium — memory scanners may detect the Donut loader stub.
//
// References:
//   - https://github.com/Binject/go-donut
//   - https://github.com/TheWover/donut
//   - https://github.com/monoxgas/sRDI
package srdi
