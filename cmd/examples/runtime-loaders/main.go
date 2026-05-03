//go:build windows

// runtime-loaders — panorama 14 of the doc-truth audit.
//
// Built strictly from the user-facing markdown:
//   - docs/techniques/runtime/bof-loader.md       — bof.Load
//   - docs/techniques/runtime/clr.md              — clr.Load + ExecuteAssembly
//   - docs/techniques/injection/module-stomping.md — inject.ModuleStomp
//
// Probes API surface and the most-likely environment failure modes for
// each loader. Most of these expect a real artifact (a BOF .o, a .NET
// assembly, a stomp-friendly DLL handle); this panorama feeds synthetic
// inputs and treats the structured error from each as the matrix signal.
package main

import (
	"fmt"

	"github.com/oioio-space/maldev/inject"
	"github.com/oioio-space/maldev/runtime/bof"
	"github.com/oioio-space/maldev/runtime/clr"
)

func main() {
	// 1. BOF loader — feed empty bytes; the parser should reject with a
	//    structured error rather than crash. (bof-loader.md "Simple".)
	fmt.Println("=== bof.Load (empty input) ===")
	if _, err := bof.Load(nil); err != nil {
		fmt.Printf("Load(nil): %v\n", err)
	} else {
		fmt.Printf("Load(nil): unexpected success\n")
	}

	// 2. CLR runtime — clr.md "Simple" passes nil to use the default
	//    runtime version. ExecuteAssembly is skipped because we don't
	//    ship a .NET assembly with the panorama.
	fmt.Println("\n=== clr.Load(nil) ===")
	rt, err := clr.Load(nil)
	if err != nil {
		fmt.Printf("Load: %v\n", err)
	} else {
		fmt.Printf("Load: OK runtime instance\n")
		// Smoke-test ExecuteAssembly with an empty buffer to verify the
		// API surface compiles and produces a structured error.
		if err := rt.ExecuteAssembly(nil, nil); err != nil {
			fmt.Printf("ExecuteAssembly(nil,nil): %v\n", err)
		} else {
			fmt.Printf("ExecuteAssembly(nil,nil): unexpected success\n")
		}
		rt.Close()
	}

	// 3. ModuleStomp — module-stomping.md "Simple" stomps msftedit.dll.
	//    Use a 1-byte shellcode (single 0xC3 ret) so the example doesn't
	//    actually run anything if Execute fires. We probe the stomp call
	//    only, no callback execution.
	fmt.Println("\n=== inject.ModuleStomp(msftedit.dll, 1 byte) ===")
	addr, err := inject.ModuleStomp("msftedit.dll", []byte{0xC3})
	if err != nil {
		fmt.Printf("ModuleStomp: %v\n", err)
	} else {
		fmt.Printf("ModuleStomp: OK addr=0x%x\n", addr)
	}
}
