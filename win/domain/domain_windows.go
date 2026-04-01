//go:build windows

// Package domain provides helpers for querying Windows domain membership.
package domain

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// GetDomain returns the domain name of the machine and the join status.
// Possible status values:
//   - syscall.NetSetupDomainName
//   - syscall.NetSetupUnknownStatus
//   - syscall.NetSetupWorkgroupName
//   - syscall.NetSetupUnjoined
func GetDomain() (string, uint32, error) {
	var domain *uint16
	var status uint32

	err := syscall.NetGetJoinInformation(nil, &domain, &status)
	if err != nil {
		return "", 0, err
	}

	name := windows.UTF16PtrToString(domain)
	syscall.NetApiBufferFree((*byte)(unsafe.Pointer(domain)))

	return name, status, nil
}
