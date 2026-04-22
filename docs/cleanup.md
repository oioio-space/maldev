# Cleanup and Anti-Forensics

[<- Back to README](../README.md)

The `cleanup/` module provides post-exploitation anti-forensics: self-deletion, service hiding, secure file wiping, and timestamp manipulation.

## Packages

| Package | Description | MITRE ATT&CK | Platform |
|---------|-------------|---------------|----------|
| `cleanup/selfdelete` | Delete the running executable from disk | T1070.004 -- Indicator Removal: File Deletion | Windows |
| `cleanup/service` | Hide Windows services via DACL manipulation | T1070 -- Indicator Removal on Host | Windows |
| `cleanup/wipe` | Secure multi-pass file overwrite + delete | T1070.004 -- Indicator Removal: File Deletion | Cross-platform |
| `cleanup/timestomp` | Modify file timestamps | T1070.006 -- Indicator Removal: Timestomp | Cross-platform (full on Windows) |
| `cleanup/memory` | Secure memory wiping and deallocation | T1070 -- Indicator Removal on Host | Windows |

---

## cleanup/selfdelete -- Self-Deletion

### Run

```go
func Run() error
```

**Purpose:** Deletes the currently running executable from disk while it is still executing.

**How the NTFS ADS rename technique works:**

On NTFS, a file cannot be deleted while a process has it mapped into memory. However, NTFS alternate data streams (ADS) provide a workaround:

1. **Get the executable path** via `GetModuleFileName`.
2. **Open the file handle** with `DELETE` access and no sharing (exclusive lock).
3. **Rename the default data stream** (`:$DATA`) to `:deadbeef` using `SetFileInformationByHandle(FileRenameInfo)`. This changes which stream the file's directory entry points to. The operating system does not consider this "in use" because the original stream name no longer exists.
4. **Close the handle** (the rename is committed).
5. **Re-open the file** with `DELETE` access again.
6. **Mark for deletion** using `SetFileInformationByHandle(FileDispositionInfo)` with `DeleteFile=true`. Because the default stream was renamed, NTFS allows the deletion to proceed.
7. **Close the handle** -- the file is removed from the directory. The process continues running from its in-memory mapping.

This technique was popularized by @jonaslyk and works on Windows 10+ / Server 2016+. The `_FILE_RENAME_INFO` struct is manually laid out to match the x64 ABI (8-byte alignment for the `RootDirectory` handle field).

```go
import "github.com/oioio-space/maldev/cleanup/selfdelete"

if err := selfdelete.Run(); err != nil {
    // fallback to script-based deletion
    selfdelete.RunWithScript(3 * time.Second)
}
```

### RunForce

```go
func RunForce(retry int, duration time.Duration) error
```

**Purpose:** Retries `Run()` multiple times with a delay between attempts.

**Parameters:**
- `retry` (int) -- Maximum number of attempts.
- `duration` (time.Duration) -- Delay between retries.

**Why retry:** Backup services (OneDrive, Windows Backup) or AV scanners may hold a temporary lock on the file. Retrying after a short delay often succeeds. If the error is `ERROR_ALREADY_EXISTS` (the stream was already renamed), it is treated as success.

```go
err := selfdelete.RunForce(5, 2*time.Second)
```

### RunWithScript

```go
func RunWithScript(wait time.Duration) error
```

**Purpose:** Fallback self-deletion using a batch script.

**Parameters:**
- `wait` (time.Duration) -- How long to sleep before returning (gives the script time to start).

**How it works:**
1. Creates a temporary `.cmd` file in `%TEMP%`.
2. Writes a script that loops (`FOR /L %%A IN (0) DO ...`), attempting to delete the executable. Once the exe is gone, it deletes itself and exits.
3. Launches the script via `cmd.exe /c` with `HideWindow: true` (no visible console window).
4. If the file has the `HIDDEN` attribute, the script uses `DEL /AH` to handle it.

This method is less stealthy (creates a visible process and temp file) but works on all Windows versions and does not depend on NTFS ADS behavior.

```go
err := selfdelete.RunWithScript(3 * time.Second)
```

### MarkForDeletion

```go
func MarkForDeletion() error
```

**Purpose:** Marks the executable for deletion at the next system reboot using `MoveFileEx` with `MOVEFILE_DELAY_UNTIL_REBOOT`.

**Requires:** Administrator privileges (writes to `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations`).

**When to use:** When immediate deletion is not possible (file locked by multiple processes) and you can wait for a reboot.

```go
err := selfdelete.MarkForDeletion()
```

---

## cleanup/service -- Service Hiding

### HideService

```go
func HideService(mode Mode, hostname string, svc any) (string, error)
```

**Purpose:** Hides a Windows service by applying a restrictive DACL (Discretionary Access Control List) that denies standard users the ability to query, stop, or modify the service.

**Parameters:**
- `mode` (Mode) -- `Native` (uses Windows APIs directly) or `SC_SDSET` (uses `sc.exe sdset`).
- `hostname` (string) -- Remote machine name (empty string for local machine).
- `svc` (any) -- Either a `*mgr.Service` (from `golang.org/x/sys/windows/svc/mgr`) or a service name string.

**Returns:** For `SC_SDSET` mode, the string output from `sc.exe`; for `Native` mode, an empty string.

**The SDDL string explained:**

```text
D:(D;;DCWPDTSD;;;IU)(D;;DCWPDTSD;;;SU)(D;;DCWPDTSD;;;BA)(A;;CCSWLOCRRC;;;IU)(A;;CCSWLOCRRC;;;SU)(A;;CCSWRPWPDTLOCRRC;;;SY)(A;;CCDCSWRPWPDTLOCRSDRCWDWO;;;BA)
```

Breaking this down:

- `D:` -- This is a DACL.
- `(D;;DCWPDTSD;;;IU)` -- **Deny** Interactive Users: `DC` (Delete Child) + `WP` (Write Property) + `DT` (Delete Tree) + `SD` (Standard Delete). This prevents normal users from stopping, deleting, or modifying the service.
- `(D;;DCWPDTSD;;;SU)` -- Same deny for Service Users.
- `(D;;DCWPDTSD;;;BA)` -- Same deny for Built-in Administrators (they can still override via ownership, but `services.msc` will show access denied).
- `(A;;CCSWLOCRRC;;;IU)` -- **Allow** Interactive Users: basic query rights (`CC`=Connect, `SW`=Enumerate, `LO`=List Object, `CR`=Control, `RC`=Read Control).
- `(A;;CCDCSWRPWPDTLOCRSDRCWDWO;;;BA)` -- Allow Administrators full control (but the deny ACEs above take precedence in the ACL evaluation order).

The deny ACEs are listed first, so they are evaluated before the allow ACEs. This means even administrators get "access denied" when trying to modify the service through normal tools.

**Native vs SC_SDSET mode:**
- `Native` calls `SecurityDescriptorFromString` to parse the SDDL, extracts the DACL, then applies it via `SetNamedSecurityInfo` with `DACL_SECURITY_INFORMATION`.
- `SC_SDSET` shells out to `sc.exe sdset <service> <sddl>`. This is simpler but creates a child process (potentially logged by EDR).

```go
import "github.com/oioio-space/maldev/cleanup/service"

// Hide using native API
_, err := service.HideService(service.Native, "", "MyService")

// Hide on a remote machine using sc.exe
output, err := service.HideService(service.SC_SDSET, "DC01", "MyService")
```

### UnHideService

```go
func UnHideService(mode Mode, hostname string, svc any) (string, error)
```

**Purpose:** Restores the default Windows service DACL, making the service visible and manageable again.

The restore SDDL includes an audit SACL entry `S:(AU;FA;...;;;WD)` that logs all access by Everyone -- this is the Windows default for many services.

```go
_, err := service.UnHideService(service.Native, "", "MyService")
```

### SetServiceSecurityDescriptor

```go
func SetServiceSecurityDescriptor(hostname string, svc any, secDescStr string) error
```

**Purpose:** Applies an arbitrary SDDL security descriptor to a service. Use this if you want a custom DACL instead of the hardcoded hide/unhide strings.

### ScSdset

```go
func ScSdset(hostname string, svc any, secDescStr string) (string, error)
```

**Purpose:** Applies an SDDL string via `sc.exe sdset`. Returns the command output.

---

## cleanup/wipe -- Secure File Wiping

### File

```go
func File(path string, passes int) error
```

**Purpose:** Overwrites a file with random data, then deletes it.

**Parameters:**
- `path` (string) -- Path to the file to wipe.
- `passes` (int) -- Number of overwrite passes (minimum 1, clamped).

**How it works:**
1. Stats the file to get its size.
2. Opens it for writing.
3. For each pass:
   - Seeks to the beginning.
   - Writes `crypto/rand` random data in 4 KB chunks until the entire file is overwritten.
   - Calls `Sync()` to flush to disk.
4. Closes the file handle (required on Windows before deletion).
5. Calls `os.Remove` to delete the file.

**Why multi-pass:** On traditional spinning hard drives (HDD), residual magnetic traces may allow data recovery after a single overwrite. Multiple passes with random data reduce this risk. The Gutmann method uses 35 passes, but 3 passes with random data is generally considered sufficient for modern drives.

**Why SSD makes this unreliable:** Solid-state drives use wear leveling, which means writes may go to different physical NAND cells than the original data. The old data may persist in cells that the SSD's controller has remapped. On SSDs, the only reliable way to ensure data destruction is the ATA Secure Erase command or physical destruction. This function still provides value on SSDs by making the data unrecoverable through filesystem-level tools, but a forensic examiner with NAND-level access may still recover fragments.

```go
import "github.com/oioio-space/maldev/cleanup/wipe"

// 3-pass random overwrite + delete
err := wipe.File("/tmp/exfil.tar.gz", 3)
```

---

## cleanup/timestomp -- Timestamp Manipulation

### Set (Cross-platform)

```go
func Set(path string, atime, mtime time.Time) error
```

**Purpose:** Changes the access time and modification time of a file.

**Parameters:**
- `path` (string) -- File path.
- `atime` (time.Time) -- New access time.
- `mtime` (time.Time) -- New modification time.

**How it works:** Calls `os.Chtimes`, which maps to `utimes()` on Unix and `SetFileTime()` on Windows. On Windows, this only sets the access and modification times, not the creation time (use `SetFull` for that).

```go
import (
    "time"
    "github.com/oioio-space/maldev/cleanup/timestomp"
)

// Make the file look like it was last modified in 2020
target := time.Date(2020, 6, 15, 10, 30, 0, 0, time.UTC)
err := timestomp.Set("malware.exe", target, target)
```

### CopyFrom (Cross-platform)

```go
func CopyFrom(src, dst string) error
```

**Purpose:** Copies timestamps from one file to another.

**How it works:** Stats the source file, then applies its modification time to the destination. Note: on the cross-platform version, only the modification time is copied (access time is set to the same value).

```go
// Make our binary look like notepad.exe
err := timestomp.CopyFrom(`C:\Windows\notepad.exe`, `C:\Temp\implant.exe`)
```

### SetFull (Windows only)

```go
func SetFull(path string, ctime, atime, mtime time.Time) error
```

**Purpose:** Sets all three NTFS timestamps: creation time, access time, and modification time.

**Parameters:**
- `path` (string) -- File path.
- `ctime` (time.Time) -- New creation time.
- `atime` (time.Time) -- New access time.
- `mtime` (time.Time) -- New modification time.

**How it works:** Opens the file with `FILE_WRITE_ATTRIBUTES`, converts each `time.Time` to `windows.Filetime` via `NsecToFiletime`, then calls `SetFileTime`.

**Why SetFull matters for forensics:** NTFS stores two sets of timestamps:
- **$STANDARD_INFORMATION (SI):** Updated by the OS and user-mode APIs like `SetFileTime`. This is what `SetFull` modifies.
- **$FILE_NAME (FN):** Updated only by the NTFS driver itself (kernel mode) during certain operations like file creation and rename.

Forensic tools like Autopsy and Sleuth Kit compare SI and FN timestamps. If SI shows a 2020 date but FN shows 2024, the discrepancy is a strong indicator of timestomping. `SetFull` can only modify SI timestamps -- modifying FN timestamps requires a kernel driver or raw NTFS manipulation.

```go
import (
    "time"
    "github.com/oioio-space/maldev/cleanup/timestomp"
)

ref := time.Date(2019, 3, 10, 8, 0, 0, 0, time.UTC)
err := timestomp.SetFull(`C:\Temp\implant.exe`, ref, ref, ref)
```

### CopyFromFull (Windows only)

```go
func CopyFromFull(src, dst string) error
```

**Purpose:** Copies all three timestamps (creation, access, modification) from one file to another using Windows-native `GetFileTime`/`SetFileTime`.

**How it works:**
1. Opens the source file with `GENERIC_READ`.
2. Reads creation, access, and modification times via `GetFileTime`.
3. Opens the destination file with `FILE_WRITE_ATTRIBUTES`.
4. Applies all three times via `SetFileTime`.

This is the most thorough cross-file timestomp on Windows -- it copies the creation time that `CopyFrom` misses.

```go
// Clone all timestamps from a legitimate system file
err := timestomp.CopyFromFull(
    `C:\Windows\System32\kernel32.dll`,
    `C:\Temp\implant.exe`,
)
```

### Forensic Detection Notes

| Technique | Modifies SI | Modifies FN | Detectable by SI/FN comparison |
|-----------|:-----------:|:-----------:|:-----------------------------:|
| `Set` | Access + Modify | No | Yes |
| `SetFull` | Create + Access + Modify | No | Yes |
| `CopyFrom` | Modify only | No | Yes |
| `CopyFromFull` | Create + Access + Modify | No | Yes |

To avoid SI/FN discrepancy detection, the timestomped file should be newly created (so FN matches SI naturally) rather than an existing file with a different FN creation time.

---

## cleanup/memory -- Secure Memory Wiping

Package `memory` provides secure memory zeroing and deallocation for sensitive data (shellcode, keys, decrypted payloads). Ensures that memory contents cannot be recovered from process dumps or forensic analysis.

**MITRE ATT&CK:** T1070 (Indicator Removal on Host)
**Platform:** Windows
**Detection:** Low -- memory deallocation is normal process behavior.

### Functions

#### `WipeAndFree`

```go
func WipeAndFree(addr, size uintptr) error
```

**Purpose:** Zeros a memory region and releases it. The region must have been allocated with `VirtualAlloc` (`MEM_COMMIT`).

**Parameters:**
- `addr` -- Base address of the memory region.
- `size` -- Size of the region in bytes.

**How it works:**
1. Changes page protection to `PAGE_READWRITE` (the region may be `RX` or `PAGE_NOACCESS`).
2. Zeros every byte via `SecureZero`.
3. Releases the pages with `VirtualFree(MEM_RELEASE)`.

**When to use:** After shellcode execution completes, after decryption keys are no longer needed, or before process exit to minimize forensic artifacts in memory dumps.

**Example:**

```go
import "github.com/oioio-space/maldev/cleanup/memory"

// After shellcode has finished executing
err := memory.WipeAndFree(shellcodeAddr, shellcodeSize)
if err != nil {
    log.Printf("memory cleanup failed: %v", err)
}
```

---

#### `SecureZero`

```go
func SecureZero(buf []byte)
```

**Purpose:** Overwrites a byte slice with zeros in a way that the compiler cannot optimize away.

**Parameters:**
- `buf` -- Byte slice to zero. No-op if empty.

**How it works:** Writes zeros through a volatile-like pointer and calls `runtime.KeepAlive` to prevent dead-store elimination. This is critical because the Go compiler (and LLVM/GCC for CGo) may eliminate zeroing writes to memory that is not read afterwards.

**When to use:** For zeroing sensitive data in Go-managed memory (byte slices, structs) that cannot be freed with `VirtualFree`.

**Example:**

```go
import "github.com/oioio-space/maldev/cleanup/memory"

key := []byte("supersecretkey123")
defer memory.SecureZero(key)
// ... use key for decryption ...
```
