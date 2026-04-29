---
last_reviewed: 2026-04-27
reflects_commit: 57c853b
---

# Kernel-mode primitives (`kernel/*`)

[← maldev README](../../../README.md) · [docs/index](../../index.md)

The `kernel/*` package tree exposes **userland-callable kernel
read/write primitives** by abusing signed-but-vulnerable third-party
drivers (BYOVD). Userland obtains kernel R/W without loading an
unsigned driver — defeats HVCI on hosts older than the 2021-09
vulnerable-driver block-list update.

```mermaid
flowchart LR
    Caller -->|Driver.Install| Lifecycle["NtLoadDriver +<br>SCM CreateService/Start"]
    Lifecycle --> SignedSys["RTCore64.sys (signed)"]
    SignedSys --> IOCTL["IOCTL 0x80002048 / 0x8000204C"]
    IOCTL --> Kernel["arbitrary kernel R/W"]
    Kernel -->|consumed by| KCB["evasion/kcallback"]
    Kernel -->|consumed by| LSASS["credentials/lsassdump"]
```

## Decision tree

| Operator question | Package / page |
|---|---|
| "I need to wipe a kernel-callback array." | [`evasion/kcallback`](../evasion/kernel-callback-removal.md) feeds on this primitive |
| "I need to dump LSASS bypassing PPL." | [`credentials/lsassdump`](../credentials/lsassdump.md) |
| "I need a signed BYOVD driver to install." | [`kernel/driver/rtcore64`](byovd-rtcore64.md) |

## Per-package pages

- [byovd-rtcore64.md](byovd-rtcore64.md) — RTCore64.sys
  (CVE-2019-16098). Microsoft-attested signed; refused on HVCI hosts
  ≥ 2021-09 vulnerable-driver block-list.

## Common contract

Every concrete BYOVD driver implements three interfaces from the
umbrella package:

- [`kernel/driver.Reader`](https://pkg.go.dev/github.com/oioio-space/maldev/kernel/driver#Reader)
  — `ReadKernel(addr, buf) (int, error)`.
- [`kernel/driver.ReadWriter`](https://pkg.go.dev/github.com/oioio-space/maldev/kernel/driver#ReadWriter)
  — adds `WriteKernel(addr, data)`.
- [`kernel/driver.Lifecycle`](https://pkg.go.dev/github.com/oioio-space/maldev/kernel/driver#Lifecycle)
  — `Install / Uninstall / Loaded`. Idempotent install; best-effort
  uninstall.

Sentinel errors: `ErrNotImplemented`, `ErrNotLoaded`,
`ErrPrivilegeRequired` (caller lacks SeLoadDriverPrivilege).

## MITRE ATT&CK rollup

| ID | Technique | Owners |
|---|---|---|
| T1014 | Rootkit | kernel/driver, kernel/driver/rtcore64 |
| T1543.003 | Create or Modify System Process: Windows Service | service install path |
| T1068 | Exploitation for Privilege Escalation | IOCTL R/W primitive |

## See also

- [`docs/techniques/evasion/kernel-callback-removal.md`](../evasion/kernel-callback-removal.md)
- [`docs/techniques/credentials/lsassdump.md`](../credentials/lsassdump.md)
- [`docs/architecture.md`](../../architecture.md) — layering rules
