//go:build windows

// Package domain provides helpers for querying Windows domain membership
// including domain name retrieval and join status detection.
//
// Platform: Windows
// Detection: Low -- uses standard NetGetJoinInformation API.
//
// Example:
//
//	name, status, err := domain.Name()
//	if status == syscall.NetSetupDomainName {
//	    fmt.Printf("Joined to domain: %s\n", name)
//	}
package domain
