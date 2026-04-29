---
last_reviewed: 2026-04-27
reflects_commit: 57c853b
---

# Privilege escalation (`privesc/*`)

[← maldev README](../../../README.md) · [docs/index](../../index.md)

The `privesc/*` package tree groups primitives that take a
non-elevated user token and produce SYSTEM-context execution.

```mermaid
flowchart TB
    subgraph startState [Start state]
        Medium["Medium-IL token<br>(typical user)"]
    end
    subgraph paths [Escalation paths]
        UAC["uac/*<br>fodhelper / slui /<br>silentcleanup / eventvwr"]
        CVE["cve202430088/*<br>kernel TOCTOU race"]
    end
    subgraph end [End state]
        High["High-IL token (UAC)"]
        SYSTEM["NT AUTHORITY\\SYSTEM<br>(token swap)"]
    end
    Medium -->|admin user, UAC default| UAC
    UAC --> High
    Medium -->|vulnerable build < 2024-06| CVE
    CVE --> SYSTEM
```

## Decision tree

| State / question | Path |
|---|---|
| "User is admin, UAC is default-notify, just need elevation." | [`privesc/uac`](uac.md) — pick the bypass that survives the build |
| "Need SYSTEM, host build < June 2024 patch." | [`privesc/cve202430088`](cve202430088.md) |
| "Already SYSTEM, need TrustedInstaller." | [`win/impersonate.RunAsTrustedInstaller`](../tokens/impersonation.md) |
| "Already admin, need elevation without UAC bypass." | [`win/privilege.ShellExecuteRunAs`](../tokens/privilege-escalation.md) (visible UAC prompt) |

## Per-package pages

- [uac.md](uac.md) — four bypass primitives (FODHelper, SLUI,
  SilentCleanup, EventVwr) with build-window tables.
- [cve202430088.md](cve202430088.md) — CVE-2024-30088 kernel TOCTOU
  race with pre-flight version probe and BSOD-risk caveat.

## Pre-flight pattern

```go
import (
    "github.com/oioio-space/maldev/win/version"
    "github.com/oioio-space/maldev/win/privilege"
)

admin, elevated, _ := privilege.IsAdmin()
switch {
case elevated:
    // already there
case admin && !elevated:
    // UAC bypass
case !admin:
    // CVE path or credential capture
}

if info, _ := version.CVE202430088(); info.Vulnerable {
    // kernel race available
}
```

## MITRE ATT&CK rollup

| ID | Technique | Owners |
|---|---|---|
| T1548.002 | Bypass User Account Control | privesc/uac |
| T1068 | Exploitation for Privilege Escalation | privesc/cve202430088 |
| T1134.001 | Token Impersonation/Theft | privesc/cve202430088 (token swap) |

## See also

- [`docs/techniques/tokens/`](../tokens/) — token-level primitives
- [`docs/techniques/win/version.md`](../win/version.md) — pre-flight version + UBR probe
- [`docs/privilege.md`](../../privilege.md) — operator-facing privilege overview
