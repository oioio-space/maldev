//go:build windows

// Package user provides Windows local user account management via NetAPI32.
//
// Technique: Local account creation, deletion, and group membership modification.
// MITRE ATT&CK: T1136.001 (Create Account: Local Account).
// Detection: High -- account creation and modification generates Windows Security
// event logs (4720, 4722, 4732, 4724) that are typically monitored by SIEM.
// Platform: Windows.
//
// How it works: Calls NetUserAdd, NetUserDel, NetUserSetInfo, NetUserEnum, and
// NetLocalGroupAddMembers / NetLocalGroupDelMembers to manage local user accounts
// and their group memberships. These are standard administrative APIs backed by
// the SAM database.
//
// Limitations:
//   - Most operations require local administrator privileges.
//   - Account events are logged even if audit policy is not explicitly configured
//     on modern Windows versions.
//   - Domain-joined machines may have Group Policy restrictions on local accounts.
//
// Example:
//
//	user.Add("svc-update", "P@ssw0rd!2024")
//	user.SetAdmin("svc-update")
//	defer user.Delete("svc-update")
package user
