// Package srdi provides DLL-to-shellcode conversion using
// Shellcode Reflective DLL Injection (sRDI) techniques.
//
// sRDI converts a standard Windows DLL into position-independent shellcode
// that can be injected into any process. The generated shellcode contains a
// minimal reflective loader that:
//
//  1. Walks the PEB to find kernel32.dll
//  2. Resolves VirtualAlloc, LoadLibraryA, GetProcAddress
//  3. Maps PE sections into freshly allocated memory
//  4. Processes base relocations for the new address
//  5. Resolves the import table
//  6. Calls TLS callbacks
//  7. Invokes DllMain (or a specified export function)
//
// Usage:
//
//	cfg := srdi.DefaultConfig()
//	cfg.FunctionName = "MyExport"       // optional: call a specific export
//	cfg.ClearHeader = true              // evasion: wipe PE header after load
//
//	shellcode, err := srdi.ConvertDLL("payload.dll", cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	// shellcode is now ready for injection
//
// Technique: Shellcode Reflective DLL Injection (sRDI)
// MITRE ATT&CK: T1055.001 (Process Injection: DLL Injection)
// Platform: Cross-platform (generates Windows x64 shellcode)
// Detection: Medium -- the generated shellcode loads a DLL from memory
// without touching disk, but memory scanners may detect the reflective loader
// pattern or the loaded PE in memory.
//
// References:
//   - https://github.com/monoxgas/sRDI (original sRDI by Nick Landers)
//   - https://github.com/stephenfewer/ReflectiveDLLInjection
package srdi
