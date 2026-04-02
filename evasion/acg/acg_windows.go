//go:build windows

package acg

import (
	"fmt"
	"unsafe"

	"github.com/oioio-space/maldev/win/api"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
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
//
// SetProcessMitigationPolicy is a kernel32 export with no NT equivalent
// routable through the Caller (NtSetInformationProcess uses a different info
// class for mitigation policies and is not publicly documented for this use).
// The caller parameter is accepted for evasion.Technique API consistency but
// cannot bypass kernel32 hooks for this specific technique.
func Enable(caller *wsyscall.Caller) error {
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
