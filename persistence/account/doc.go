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
