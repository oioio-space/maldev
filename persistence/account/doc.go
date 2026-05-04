//go:build windows

// Package user provides Windows local user account management
// via NetAPI32 — create, delete, set password, manage group
// membership, enumerate.
//
// Uses standard administrative APIs backed by the SAM database:
// `NetUserAdd`, `NetUserDel`, `NetUserSetInfo`, `NetUserEnum`,
// `NetLocalGroupAddMembers` / `NetLocalGroupDelMembers`. The
// directory is named `account` for organisation; the package
// itself is `user` (the Win32 API surface name).
//
// Operationally, account-creation persistence is the loudest
// option in the persistence/* tree: every create / modify
// emits Security event 4720 / 4722 / 4732 / 4724 regardless of
// audit policy on modern Windows.
//
// # MITRE ATT&CK
//
//   - T1136.001 (Create Account: Local Account)
//   - T1098 (Account Manipulation) — group-membership changes
//
// # Detection level
//
// noisy
//
// Account creation and modification generates Windows Security
// event logs (4720 add, 4722 enable, 4732 group-member add,
// 4724 password reset) that any mature SIEM monitors. Audit
// policy is enabled by default on modern Windows; suppressing
// the events requires kernel-level tampering out of this
// package's scope.
//
// # Required privileges
//
// admin. `NetUserAdd`, `NetUserSetInfo`,
// `NetLocalGroupAddMembers` against the local SAM all require
// membership in the local Administrators group (or the
// equivalent SAM-Domain `WRITE_DAC` rights, which non-admin
// users do not hold). SYSTEM works without elevation.
// `NetUserEnum` is read-only and runs unprivileged for the
// info levels exposed here.
//
// # Platform
//
// Windows-only (`//go:build windows`). NetAPI32 is the
// Windows-only LM/SMB management surface — no POSIX
// equivalent. Cross-platform analogues would touch
// `/etc/passwd` + `/etc/shadow` (Linux) which is not wired up.
//
// # Example
//
// See [ExampleAdd] in account_example_test.go.
//
// # See also
//
//   - docs/techniques/persistence/account.md
//   - [github.com/oioio-space/maldev/persistence/service] — pair with service persistence to run as the new account
//   - [github.com/oioio-space/maldev/credentials] — pair with credential dumping for stealthier alternatives
//
// [github.com/oioio-space/maldev/persistence/service]: https://pkg.go.dev/github.com/oioio-space/maldev/persistence/service
// [github.com/oioio-space/maldev/credentials]: https://pkg.go.dev/github.com/oioio-space/maldev/credentials
package user
