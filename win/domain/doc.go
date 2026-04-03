//go:build windows

// Package domain provides helpers for querying Windows domain membership.
//
// Technique: Domain membership enumeration for environment discovery.
// MITRE ATT&CK: T1082 (System Information Discovery).
// Detection: Low — uses standard NetGetJoinInformation API.
// Platform: Windows.
//
// How it works: Calls NetGetJoinInformation to retrieve the domain or workgroup
// name and join status (domain-joined, workgroup, unjoined). The result
// indicates whether the machine is part of an Active Directory domain,
// which informs lateral movement and credential relay decisions.
//
// Limitations:
//   - Returns the NetBIOS domain name, not the FQDN. Use LDAP queries
//     for the full DNS domain name.
//   - Requires no special privileges (any user can query join status).
//
// Example:
//
//	name, status, _ := domain.Name()
//	if status == domain.StatusDomain {
//	    fmt.Printf("Joined to domain: %s\n", name)
//	}
package domain
