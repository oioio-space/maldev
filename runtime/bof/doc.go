// Package bof provides a minimal Beacon Object File (BOF) loader for
// in-memory COFF execution.
//
// Technique: In-memory COFF object file loading and execution.
// MITRE ATT&CK: T1059 (Command and Scripting Interpreter)
// Platform: Windows (amd64)
// Detection: Medium — executable memory allocation is visible to EDR, but
// the payload never touches disk and runs inside the calling process.
//
// How it works:
//
// A BOF is a compiled COFF (.o) object file. The loader parses the COFF
// header, locates the .text section containing machine code, applies
// relocations, resolves the entry point symbol from the symbol table,
// and executes it from RWX memory. This avoids writing a full PE to disk
// and leverages the same format used by Cobalt Strike's inline-execute.
//
// Limitations:
//   - Only basic COFF relocation types are supported (IMAGE_REL_AMD64_ADDR64,
//     IMAGE_REL_AMD64_ADDR32NB, IMAGE_REL_AMD64_REL32).
//   - Beacon API functions (BeaconOutput, BeaconFormatAlloc, etc.) are NOT
//     resolved. BOFs that call Beacon APIs will crash.
//   - Only x64 COFF files are supported (Machine == 0x8664).
//
// Example:
//
//	data, _ := os.ReadFile("mybof.o")
//	b, err := bof.Load(data)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	output, err := b.Execute(nil)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(string(output))
package bof
