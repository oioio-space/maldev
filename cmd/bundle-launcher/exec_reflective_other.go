//go:build !linux

package main

import "fmt"

// executePayloadReflective stub on non-Linux platforms. Reflective
// in-process loading depends on `pe/packer/runtime`'s Linux mapper
// (PT_LOAD mmap, R_X86_64_RELATIVE relocs, auxv patching). The
// Windows reflective loader is queued for a future minor; macOS will
// not see one (no operational scenario in this repo's threat model).
//
// Caller can re-run the launcher without `MALDEV_REFLECTIVE=1` to
// fall back to the default temp+exec path.
func executePayloadReflective(payload []byte, args []string) error {
	return fmt.Errorf("bundle-launcher: reflective load not supported on this OS")
}
