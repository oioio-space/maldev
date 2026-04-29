//go:build windows

package service

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SeServiceLogonRight is the LSA-managed right that an account needs
// before SCM accepts it as ServiceStartName for a service install.
// Granting it is policy-level — once installed it survives reboots
// until explicitly removed via [LsaRemoveAccountRights].
const SeServiceLogonRight = "SeServiceLogonRight"

// ErrLsaCallFailed wraps a non-zero NTSTATUS returned by an LSA API.
// Use errors.Is to discriminate the LSA error path from other Windows
// errors raised in the same code flow.
var ErrLsaCallFailed = errors.New("persistence/service: LSA call failed")

// POLICY_CREATE_ACCOUNT (0x0010) | POLICY_LOOKUP_NAMES (0x0800).
// LsaAddAccountRights only requires POLICY_CREATE_ACCOUNT once the
// SID is pre-resolved; LOOKUP_NAMES is kept so future
// LsaEnumerateAccountRights / LsaRemoveAccountRights callers don't
// need to widen the mask.
const policyCreateAccountAndLookupNames = 0x0010 | 0x0800

var (
	advapi32                  = windows.NewLazySystemDLL("advapi32.dll")
	procLsaOpenPolicy         = advapi32.NewProc("LsaOpenPolicy")
	procLsaClose              = advapi32.NewProc("LsaClose")
	procLsaAddAccountRights   = advapi32.NewProc("LsaAddAccountRights")
	procLsaNtStatusToWinError = advapi32.NewProc("LsaNtStatusToWinError")
)

func ntStatusErr(stage string, status uintptr) error {
	if status == 0 {
		return nil
	}
	winErr, _, _ := procLsaNtStatusToWinError.Call(status)
	return fmt.Errorf("%w: %s: NTSTATUS 0x%08x → Win32 %d (%w)",
		ErrLsaCallFailed, stage, uint32(status), uint32(winErr),
		windows.Errno(winErr))
}

// GrantSeServiceLogonRight adds [SeServiceLogonRight] to account on
// the local machine. account follows the same naming conventions as
// [Config.Account]: ".\\<user>", "<DOMAIN>\\<user>", or
// "NT AUTHORITY\\<builtin>".
//
// Requires the calling process to hold administrative privileges and
// SeSecurityPrivilege (typical for an interactive admin shell).
//
// Idempotent — granting an already-held right returns nil.
func GrantSeServiceLogonRight(account string) error {
	return modifyAccountRights(account, SeServiceLogonRight)
}

func modifyAccountRights(account, right string) error {
	if account == "" {
		return fmt.Errorf("persistence/service: account must not be empty")
	}

	sid, _, _, err := windows.LookupSID("", account)
	if err != nil {
		return fmt.Errorf("LookupSID(%q): %w", account, err)
	}

	var oa windows.OBJECT_ATTRIBUTES
	oa.Length = uint32(unsafe.Sizeof(oa))
	var policy windows.Handle
	status, _, _ := procLsaOpenPolicy.Call(
		0, // SystemName == NULL → local machine
		uintptr(unsafe.Pointer(&oa)),
		uintptr(policyCreateAccountAndLookupNames),
		uintptr(unsafe.Pointer(&policy)),
	)
	if err := ntStatusErr("LsaOpenPolicy", status); err != nil {
		return err
	}
	defer procLsaClose.Call(uintptr(policy))

	rightStr, err := windows.NewNTUnicodeString(right)
	if err != nil {
		return fmt.Errorf("utf16(%q): %w", right, err)
	}
	rights := [1]windows.NTUnicodeString{*rightStr}
	status, _, _ = procLsaAddAccountRights.Call(
		uintptr(policy),
		uintptr(unsafe.Pointer(sid)),
		uintptr(unsafe.Pointer(&rights[0])),
		1,
	)
	runtime.KeepAlive(rightStr)
	return ntStatusErr("LsaAddAccountRights", status)
}
