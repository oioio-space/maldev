// Builds via testdata/Makefile (target: winpanic):
//
//	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
//	  go build -ldflags='-s -w' -o winpanic.exe ./winpanic.go
//
// Phase 2-F-3-c-3 fixture for the EXCEPTION (.pdata) walker.
// Triggers a hardware exception (nil pointer dereference) which
// the OS hands to ntdll → Go's Vectored Exception Handler →
// converts to a Go panic. The VEH path uses RtlVirtualUnwind to
// walk the stack, which reads the .pdata (RUNTIME_FUNCTION) array
// + UNWIND_INFO blocks. If any RVA inside that data is stale
// after a Phase 2-F-3-c VA shift, the unwinder blows up with
// "Stack consistency check failed" or similar BEFORE Go's defer/
// recover gets a chance to fire.
//
// On a healthy binary this prints "recovered=runtime error:
// invalid memory address or nil pointer dereference stack=N"
// where N is a non-zero stack depth, then exits 0.
//
// Note: this file lives under pe/packer/testdata which Go's
// build system ignores — the package literal exists only so the
// `go build ./winpanic.go` invocation can find a main.

package main

import (
	"fmt"
	"runtime"
)

func main() {
	defer func() {
		if r := recover(); r != nil {
			pcs := make([]uintptr, 32)
			n := runtime.Callers(0, pcs)
			fmt.Printf("recovered=%v stack=%d\n", r, n)
		}
	}()
	var p *int
	_ = *p
}
