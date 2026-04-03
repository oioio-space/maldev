//go:build windows

package domain

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// JoinStatus represents the domain join status of the machine.
type JoinStatus uint32

const (
	StatusUnknown   JoinStatus = 0 // NetSetupUnknownStatus
	StatusUnjoined  JoinStatus = 1 // NetSetupUnjoined
	StatusWorkgroup JoinStatus = 2 // NetSetupWorkgroupName
	StatusDomain    JoinStatus = 3 // NetSetupDomainName
)

// String returns the MSDN constant name for the join status.
func (s JoinStatus) String() string {
	switch s {
	case StatusUnknown:
		return "NetSetupUnknownStatus"
	case StatusUnjoined:
		return "NetSetupUnjoined"
	case StatusWorkgroup:
		return "NetSetupWorkgroupName"
	case StatusDomain:
		return "NetSetupDomainName"
	default:
		return fmt.Sprintf("JoinStatus(%d)", s)
	}
}

// Name returns the domain/workgroup name of the machine and the join status.
func Name() (string, JoinStatus, error) {
	var domainPtr *uint16
	var status uint32

	err := syscall.NetGetJoinInformation(nil, &domainPtr, &status)
	if err != nil {
		return "", StatusUnknown, err
	}

	name := windows.UTF16PtrToString(domainPtr)
	syscall.NetApiBufferFree((*byte)(unsafe.Pointer(domainPtr)))

	return name, JoinStatus(status), nil
}
