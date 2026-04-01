//go:build windows

package acg

import (
	"fmt"
	"unsafe"

	"github.com/oioio-space/maldev/win/api"
)

// processDynamicCodePolicy is the policy ID for Arbitrary Code Guard.
const processDynamicCodePolicy = 2

// dynamicCodePolicy matches the PROCESS_MITIGATION_DYNAMIC_CODE_POLICY struct.
// Setting ProhibitDynamicCode=1 prevents the process from generating dynamic code.
type dynamicCodePolicy struct {
	Flags uint32
}

// Enable activates Arbitrary Code Guard for the current process.
// Once enabled, the process cannot allocate new executable memory (PAGE_EXECUTE_*).
// This blocks EDR from injecting dynamic hooks but also prevents shellcode execution.
//
// Requires Windows 10 1709+. Returns error on older versions.
func Enable() error {
	policy := dynamicCodePolicy{Flags: 1} // ProhibitDynamicCode = 1
	r, _, err := api.ProcSetProcessMitigationPolicy.Call(
		uintptr(processDynamicCodePolicy),
		uintptr(unsafe.Pointer(&policy)),
		unsafe.Sizeof(policy),
	)
	if r == 0 {
		return fmt.Errorf("SetProcessMitigationPolicy(ACG): %w", err)
	}
	return nil
}
