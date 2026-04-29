//go:build windows

package service

import (
	"errors"
	"fmt"
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

// lsaUnicodeString mirrors LSA_UNICODE_STRING (NTSecAPI.h). All three
// fields hold byte counts (Length / MaximumLength) — *not* WCHAR
// counts — and Buffer points at a UTF-16 sequence that does not need
// to be NUL-terminated.
type lsaUnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

// lsaObjectAttributes is enough for LSA — every field is documented
// as "must be NULL" except RootDirectory (also NULL), so a zero value
// suffices. Defined here to avoid a dependency on the wider
// OBJECT_ATTRIBUTES marshalling.
type lsaObjectAttributes struct {
	Length                   uint32
	RootDirectory            windows.Handle
	ObjectName               *lsaUnicodeString
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

// POLICY_CREATE_ACCOUNT (0x0010) | POLICY_LOOKUP_NAMES (0x0800) — the
// minimum access mask required to add an account-rights record.
const policyCreateAccountAndLookupNames = 0x0010 | 0x0800

var (
	advapi32                  = windows.NewLazySystemDLL("advapi32.dll")
	procLsaOpenPolicy         = advapi32.NewProc("LsaOpenPolicy")
	procLsaClose              = advapi32.NewProc("LsaClose")
	procLsaAddAccountRights   = advapi32.NewProc("LsaAddAccountRights")
	procLsaNtStatusToWinError = advapi32.NewProc("LsaNtStatusToWinError")
)

// makeLsaUnicodeString returns a lsaUnicodeString backed by a freshly
// allocated UTF-16 buffer. The caller must keep the returned []uint16
// alive (via runtime.KeepAlive or by stack-rooting it) for the
// lifetime of any pointer derived from the struct.
func makeLsaUnicodeString(s string) (lsaUnicodeString, []uint16, error) {
	if s == "" {
		return lsaUnicodeString{}, nil, nil
	}
	buf, err := windows.UTF16FromString(s)
	if err != nil {
		return lsaUnicodeString{}, nil, fmt.Errorf("utf16(%q): %w", s, err)
	}
	// Drop the trailing NUL — LSA wants byte counts of the string body.
	bodyLen := uint16(2 * (len(buf) - 1))
	return lsaUnicodeString{
		Length:        bodyLen,
		MaximumLength: bodyLen,
		Buffer:        &buf[0],
	}, buf, nil
}

// ntStatusErr converts a non-zero NTSTATUS into a Go error. Goes
// through LsaNtStatusToWinError (advapi32) so the resulting Win32
// error code matches what `net helpmsg` decodes.
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

	// 1. Resolve account → SID via LookupAccountName.
	sid, _, _, err := windows.LookupSID("", account)
	if err != nil {
		return fmt.Errorf("LookupSID(%q): %w", account, err)
	}

	// 2. Open the local LSA policy with the rights we need.
	var oa lsaObjectAttributes
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

	// 3. Marshal the right name as an LSA_UNICODE_STRING array of length 1.
	rightStr, rightBuf, err := makeLsaUnicodeString(right)
	if err != nil {
		return err
	}
	rights := [1]lsaUnicodeString{rightStr}
	_ = rightBuf // keep alive

	// 4. LsaAddAccountRights(policy, sid, &rights[0], 1).
	status, _, _ = procLsaAddAccountRights.Call(
		uintptr(policy),
		uintptr(unsafe.Pointer(sid)),
		uintptr(unsafe.Pointer(&rights[0])),
		1,
	)
	return ntStatusErr("LsaAddAccountRights", status)
}
