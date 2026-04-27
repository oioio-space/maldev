---
last_reviewed: 2026-04-27
reflects_commit: b75160a
---

# Collection techniques

[← maldev README](../../../README.md) · [docs/index](../../index.md)

The `collection/*` package tree groups **local data-acquisition primitives**
for post-exploitation: keystrokes, clipboard contents, screen captures.
Each sub-package is self-contained and Windows-only — pick the data source
the operator needs and import the matching package.

```mermaid
flowchart LR
    subgraph user [User session]
        KB[Keyboard input]
        CB[Clipboard]
        FB[Framebuffer]
    end
    subgraph collection [collection/*]
        K[keylog<br/>WH_KEYBOARD_LL hook]
        C[clipboard<br/>OpenClipboard + seq poll]
        S[screenshot<br/>GDI BitBlt]
    end
    subgraph sink [Operator sink]
        OUT[stdout / file / C2 channel]
    end
    KB --> K
    CB --> C
    FB --> S
    K -. Ctrl+V .-> C
    K --> OUT
    C --> OUT
    S --> OUT
```

## Packages

| Package | Tech page | Detection | One-liner |
|---|---|---|---|
| [`collection/keylog`](../../../collection/keylog) | [keylogging.md](keylogging.md) | noisy | low-level keyboard hook with per-event window/process attribution and Ctrl+V clipboard capture |
| [`collection/clipboard`](../../../collection/clipboard) | [clipboard.md](clipboard.md) | quiet | one-shot `ReadText` plus `Watch` channel driven by `GetClipboardSequenceNumber` polling |
| [`collection/screenshot`](../../../collection/screenshot) | [screenshot.md](screenshot.md) | quiet | GDI `BitBlt` → PNG; primary, arbitrary rectangle, or per-monitor capture |

## Quick decision tree

| You want to… | Use |
|---|---|
| …record what the user types, with window context | [`keylog.Start`](keylogging.md) |
| …also capture pasted credentials | [`keylog.Start`](keylogging.md) — Ctrl+V auto-snapshots clipboard into the event |
| …read clipboard once (e.g. after `runas`) | [`clipboard.ReadText`](clipboard.md) |
| …stream clipboard changes for a session | [`clipboard.Watch`](clipboard.md) |
| …grab the primary monitor as PNG | [`screenshot.Capture`](screenshot.md) |
| …enumerate monitors first, then capture one | [`screenshot.DisplayCount`](screenshot.md) → [`CaptureDisplay`](screenshot.md) |
| …crop to a specific UI region (e.g. an open RDP window) | [`screenshot.CaptureRect`](screenshot.md) |

## MITRE ATT&CK

| T-ID | Name | Packages | D3FEND counter |
|---|---|---|---|
| [T1056.001](https://attack.mitre.org/techniques/T1056/001/) | Input Capture: Keylogging | `collection/keylog` | [D3-PA](https://d3fend.mitre.org/technique/d3f:ProcessAnalysis/) |
| [T1115](https://attack.mitre.org/techniques/T1115/) | Clipboard Data | `collection/clipboard`, `collection/keylog` (paste capture) | [D3-PA](https://d3fend.mitre.org/technique/d3f:ProcessAnalysis/) |
| [T1113](https://attack.mitre.org/techniques/T1113/) | Screen Capture | `collection/screenshot` | [D3-PA](https://d3fend.mitre.org/technique/d3f:ProcessAnalysis/) |

## Cross-referenced techniques

Two adjacent collection workflows live under sibling areas. They are
listed here as a navigation convenience; their canonical homes are the
packages that own them.

| Area concern | Tech page | Owning package |
|---|---|---|
| NTFS Alternate Data Streams (hide collected data in `:stream` suffixes) | [alternate-data-streams.md](alternate-data-streams.md) | [`cleanup/ads`](../cleanup/README.md) |
| LSASS minidump (in-process MINIDUMP assembly via `NtReadVirtualMemory`) | [lsass-dump.md](lsass-dump.md) | [`credentials/lsassdump`](../../../credentials/lsassdump) |

> [!NOTE]
> Both pages will move to their owning areas in Phase 6 of the doc
> refactor (see [docs/refactor-2026-doc/progress.md](../../refactor-2026-doc/progress.md)).

## See also

- [Operator path: post-exploitation collection](../../by-role/operator.md)
- [Detection eng path: collection telemetry](../../by-role/detection-eng.md)
- [`c2/transport`](../c2/README.md) — exfiltrate captured data over the
  established channel.
- [`crypto`](../crypto/README.md) — encrypt collected blobs before
  staging or transmission.
- [`cleanup`](../cleanup/README.md) — wipe collection artefacts after
  exfiltration.
