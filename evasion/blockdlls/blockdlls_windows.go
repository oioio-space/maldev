//go:build windows

package blockdlls

import (
	"fmt"
	"unsafe"

	"github.com/oioio-space/maldev/win/api"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// processMitigationBinarySignaturePolicy is the policy ID (8).
const processMitigationBinarySignaturePolicy = 8

// binarySignaturePolicy matches PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY.
type binarySignaturePolicy struct {
	Flags uint32
}

// Enable blocks loading of non-Microsoft-signed DLLs into the current process.
// This prevents EDR/AV DLL injection since their DLLs are typically not Microsoft-signed.
//
// WARNING: This may break legitimate third-party DLLs loaded by the process.
// Requires Windows 10 1709+.
//
// TODO: Use caller for NtSetInformationProcess when non-nil.
func Enable(caller *wsyscall.Caller) error {
	_ = caller // reserved for future syscall method support
	policy := binarySignaturePolicy{Flags: 1} // MicrosoftSignedOnly = 1
	r, _, err := api.ProcSetProcessMitigationPolicy.Call(
		uintptr(processMitigationBinarySignaturePolicy),
		uintptr(unsafe.Pointer(&policy)),
		unsafe.Sizeof(policy),
	)
	if r == 0 {
		return fmt.Errorf("SetProcessMitigationPolicy(BlockDLLs): %w", err)
	}
	return nil
}
