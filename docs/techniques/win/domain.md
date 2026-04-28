---
last_reviewed: 2026-04-27
reflects_commit: 57c853b
mitre: T1082
detection_level: very-quiet
---

# Domain-membership fingerprint

[← win techniques](README.md) · [docs/index](../../index.md)

## TL;DR

`domain.Name()` returns the local host's NetBIOS domain or workgroup
name plus a [`JoinStatus`] enum. One `NetGetJoinInformation`
round-trip — no LDAP, no DC contact, no privilege check. Use it to
gate domain-targeted post-exploitation flows.

> [!NOTE]
> NetBIOS name only. For the FQDN, query LDAP via
> [`recon/network`](../recon/network.md) or read the
> `Domain.UserName` from a Kerberos PAC.

## Primer

Two questions a post-ex chain needs answered before lateral movement
is worth attempting:

1. Is this host part of an Active Directory domain? (Otherwise
   AD-targeted credentials and DC enumeration are dead-ends.)
2. What is the domain name to seed those queries with?

`NetGetJoinInformation` answers both in a single call to the local
LSA over RPC — no network traffic leaves the host, no admin token
required. Mirror of what `whoami /upn` and `dsregcmd /status` do.

## How it works

```mermaid
sequenceDiagram
    Caller->>+netapi32: NetGetJoinInformation(NULL, &name, &status)
    netapi32->>+LSA: query SAM domain info
    LSA-->>-netapi32: domain/workgroup name + status
    netapi32-->>-Caller: NetSetupDomainName / NetSetupWorkgroupName / ...
    Caller->>netapi32: NetApiBufferFree(name)
```

Implementation:

1. Call `syscall.NetGetJoinInformation` (golang.org/x/sys/windows
   wrapping `netapi32!NetGetJoinInformation`).
2. Convert the returned `*uint16` to Go string.
3. Free the netapi-owned buffer with `NetApiBufferFree`.
4. Return `(name, JoinStatus, error)`.

## API Reference

```go
type JoinStatus uint32

const (
    StatusUnknown   JoinStatus = 0 // NetSetupUnknownStatus
    StatusUnjoined  JoinStatus = 1 // NetSetupUnjoined
    StatusWorkgroup JoinStatus = 2 // NetSetupWorkgroupName
    StatusDomain    JoinStatus = 3 // NetSetupDomainName
)

func (s JoinStatus) String() string
func Name() (string, JoinStatus, error)
```

### `Name() (string, JoinStatus, error)`

**Parameters:** none.

**Returns:**
- `name` — NetBIOS domain or workgroup name. Empty when status is
  `StatusUnknown` or `StatusUnjoined`.
- `status` — one of the four `Status*` constants.
- `error` — surface only when the netapi32 call itself fails (e.g.,
  `RPC_S_SERVER_UNAVAILABLE` on stripped-down OS images). On normal
  Windows hosts this never errors.

**Side effects:** none (the netapi32-allocated buffer is freed
internally before return).

**OPSEC:** silent. `NetGetJoinInformation` is in every default
Windows binary's import resolution path; user-mode RPC to local LSA
generates no Sysmon event ID.

## Examples

### Simple — bail on workgroup

```go
name, status, err := domain.Name()
if err != nil || status != domain.StatusDomain {
    return // host is not domain-joined; abort domain-targeted ops
}
log.Printf("operating in domain %q", name)
```

### Composed — gate kerberoasting

```go
import (
    "github.com/oioio-space/maldev/win/domain"
    "github.com/oioio-space/maldev/credentials/kerberoast" // hypothetical
)

func TryKerberoast(targetSPN string) error {
    _, status, _ := domain.Name()
    if status != domain.StatusDomain {
        return errors.New("kerberoast: not domain-joined")
    }
    return kerberoast.Roast(targetSPN)
}
```

### Advanced — combine with version + sandbox gates

```go
import (
    "github.com/oioio-space/maldev/win/domain"
    "github.com/oioio-space/maldev/win/version"
    "github.com/oioio-space/maldev/recon/sandbox"
)

func ShouldExpand() bool {
    if sandbox.IsLikely() {
        return false // bail in analysis envs
    }
    if !version.AtLeast(version.WINDOWS_10_1809) {
        return false // tooling assumes 1809+ APIs
    }
    _, status, _ := domain.Name()
    return status == domain.StatusDomain
}
```

## OPSEC & Detection

| Vector | Visibility | Mitigation |
|---|---|---|
| `NetGetJoinInformation` RPC | Not logged by default | None needed |
| Process integrity | Any user can call | None |
| Network traffic | Local LSA only — no DC contact | — |

This call is invisible to Sysmon, ETW Microsoft-Windows-Security
provider, and AMSI. The detection floor is "did the implant exist"
— this primitive adds no incremental signal.

## MITRE ATT&CK

- **T1082 (System Information Discovery)** — domain-membership probe
  is a host-fingerprint primitive.
- **T1016 (System Network Configuration Discovery)** — when paired
  with [`recon/network`](../recon/network.md) for DC discovery.

## Limitations

- NetBIOS name only — for FQDN use LDAP search (`(objectClass=domain)`)
  via [`recon/network`](../recon/network.md).
- Cached at machine boot — does not reflect a join/unjoin that has
  not been followed by reboot.
- No domain-trust enumeration — single-domain answer.

## See also

- [`win/version`](version.md) — companion host fingerprint
- [`recon/sandbox`](../recon/sandbox.md) — gate on environment shape
- [`recon/network`](../recon/network.md) — LDAP / DNS expansion of the domain answer
