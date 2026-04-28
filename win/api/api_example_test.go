//go:build windows

package api_test

import (
	"fmt"

	"github.com/oioio-space/maldev/win/api"
)

// ResolveByHash returns the in-process address of an export without
// any plaintext API name in the binary — the operator's caller-side
// import table is empty.
func ExampleResolveByHash() {
	addr, err := api.ResolveByHash(api.HashKernel32, api.HashLoadLibraryA)
	if err != nil {
		fmt.Println("resolve:", err)
		return
	}
	_ = addr
}

// PatchProc rewrites the first N bytes of an in-memory function — the
// classic AMSI / ETW unhook primitive. Caller passes the lazy proc
// (resolved through win/api so DLL handles are deduped repo-wide).
func ExamplePatchProc() {
	// Example only: real callers patch e.g. NtTraceEvent or AmsiScanBuffer.
	// Replace the first 3 bytes with `xor eax, eax; ret` (`33 c0 c3`).
	patch := []byte{0x33, 0xC0, 0xC3}
	_ = patch
	fmt.Println("ready to patch")
}
