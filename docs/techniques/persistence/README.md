# Persistence

[<- Back to README](../../../README.md)

**MITRE ATT&CK:** [T1547 - Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/), [T1053 - Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/), [T1543 - Create or Modify System Process](https://attack.mitre.org/techniques/T1543/)

---

## Overview

The `persistence/` package provides techniques for maintaining access across reboots. Each sub-package implements a different persistence mechanism.

## Packages

| Package | Technique | MITRE | Platform | Detection |
|---------|-----------|-------|----------|-----------|
| `persistence/registry` | Registry Run/RunOnce keys (HKCU + HKLM) | T1547.001 | Windows | Medium |
| `persistence/startup` | StartUp folder LNK shortcuts | T1547.001, T1547.009 | Windows | Medium |
| `persistence/scheduler` | Task Scheduler via schtasks.exe | T1053.005 | Windows | Medium |
| `persistence/service` | Windows Service via SCM | T1543.003 | Windows | High |

## Usage

### Registry Run Key

```go
import "github.com/oioio-space/maldev/persistence/registry"

// Install persistence in HKCU Run key
err := registry.Set(registry.HiveCurrentUser, registry.KeyRun, "MyApp", `C:\path\to\binary.exe`)

// Remove
err = registry.Delete(registry.HiveCurrentUser, registry.KeyRun, "MyApp")
```

### StartUp Folder

```go
import "github.com/oioio-space/maldev/persistence/startup"

// Create a .lnk in the user's Startup folder
err := startup.Install("MyApp", `C:\path\to\binary.exe`, "--flag")

// Remove
err = startup.Remove("MyApp")
```

### Task Scheduler

```go
import "github.com/oioio-space/maldev/persistence/scheduler"

err := scheduler.Create(ctx, &scheduler.Task{
    Name:    "MyTask",
    Command: `C:\path\to\binary.exe`,
    Trigger: scheduler.TriggerLogon,
})
```

### Windows Service

```go
import "github.com/oioio-space/maldev/persistence/service"

err := service.Install(&service.Config{
    Name:        "MySvc",
    DisplayName: "My Service",
    BinPath:     `C:\path\to\binary.exe`,
    StartType:   service.StartAuto,
})
```
