# DLL Search Order Hijacking — Discovery

[<- Back to Evasion](README.md)

**MITRE ATT&CK:** [T1574.001 — Hijack Execution Flow: DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1574/001/)
**Package:** `evasion/dllhijack`
**Platform:** Windows
**Detection:** Medium

---

## Primer

Windows resolves DLL loads along a documented search order. If a process
starts from directory `D`, that directory is searched **before** System32
for most DLL imports. When `D` is writable by an attacker's token and the
process is about to load a DLL whose name collides with one we drop into
`D`, our DLL executes in the victim process's security context.

Discovery is a two-step problem:

1. **Who is the victim?** — a running process, a service, or a
   scheduled task. Each has a well-known "working directory" from which
   search resolution starts.
2. **Is there an exploitable path?** — a directory on the search path
   that the current user can write to before the target DLL is found
   elsewhere.

`evasion/dllhijack` ships step 1 for **services** today. The API is a
recon scanner; dropping a payload DLL and validating via a canary is
future work (tracked in the package doc).

---

## How It Works

```mermaid
sequenceDiagram
    participant Scanner as dllhijack.ScanServices
    participant SCM as Service Control Manager
    participant FS as Filesystem

    Scanner->>SCM: Connect()
    Scanner->>SCM: ListServices()
    SCM-->>Scanner: [svchost, sshd, uhssvc, ...]

    loop for each service
        Scanner->>SCM: OpenService(name).Config()
        SCM-->>Scanner: BinaryPathName
        Scanner->>Scanner: ParseBinaryPath → exe, dir
        Scanner->>FS: probe write(dir, .maldev-hijack-probe)
        alt writable
            FS-->>Scanner: ok
            Scanner->>Scanner: emit Opportunity{Kind: Service, ...}
        else denied
            FS-->>Scanner: EACCES
        end
    end
    Scanner-->>Caller: []Opportunity
```

**Step-by-step:**

1. **Connect** to the SCM via `golang.org/x/sys/windows/svc/mgr`.
2. **Enumerate** every installed service (`ListServices`).
3. **Fetch config** for each — we need `BinaryPathName`.
4. **Parse** the binary path: handle quoted paths (`"C:\Program Files\svc.exe" -arg`) and unquoted paths (`C:\Windows\System32\svc.exe -k ...`).
5. **Probe writability** of the binary's directory by attempting to create a temp file there (`O_CREATE|O_WRONLY|O_EXCL`, then `os.Remove`). The probe uses the current user's token — no elevation, no pretending.
6. **Emit** an `Opportunity` for each writable dir, including the service's ID, display name, and the reason we flagged it.

The writability probe's behaviour depends on the running token:

- **Non-admin**: most Windows services are in System32 / Program Files, both protected. The scanner typically returns 0–5 candidates — third-party services in user-writable locations.
- **Admin**: every dir on the system is writable, so the scanner returns the full service list. Useful for inventorying the attack surface, not for deciding what to exploit.

---

## Usage

```go
import (
    "fmt"
    "log"
    "github.com/oioio-space/maldev/evasion/dllhijack"
)

func main() {
    opps, err := dllhijack.ScanServices()
    if err != nil { log.Fatal(err) }

    for _, o := range opps {
        fmt.Printf("%s (%s)\n", o.ID, o.DisplayName)
        fmt.Printf("  binary : %s\n", o.BinaryPath)
        fmt.Printf("  dir    : %s  (writable: %v)\n", o.SearchDir, o.Writable)
        fmt.Printf("  reason : %s\n\n", o.Reason)
    }
}
```

### Parsing `BinaryPathName` manually

`ParseBinaryPath` is exported for callers that read service config from
sources other than the SCM (registry dumps, event log exports):

```go
exe := dllhijack.ParseBinaryPath(`"C:\Program Files\Svc\svc.exe" --service`)
// exe == `C:\Program Files\Svc\svc.exe`
```

---

## Limitations

- **No import analysis.** A writable service dir is a *potential* hijack
  vector, not a confirmed one. To confirm, a Phase 2.1 helper (deferred)
  will parse the binary's imports, resolve each one against the effective
  search order, and return only the DLL names that actually resolve to
  a writable location before System32.
- **Services only.** `ScanProcesses` (via `Toolhelp32` module walk) and
  `ScanScheduledTasks` (via COM `ITaskService`) are future additions.
- **No canary.** A canary DLL with the victim's expected exports + a
  load-time log marker is needed to prove end-to-end exploitability —
  see `docs/superpowers/specs/` for the design when it lands.

---

## Comparison

| Tool                  | Ships canary validation | Covers processes | Covers services | Covers tasks | Go-native |
|-----------------------|-------------------------|------------------|-----------------|--------------|-----------|
| `maldev/dllhijack`    | no (Phase 2.1)          | no (Phase 2.1)   | **yes**         | no (Phase 2.1)| yes       |
| DLLHijackHunter (.NET)| yes                     | yes              | yes             | yes          | no        |
| Siofra (Koret)        | no                      | yes              | no              | no           | no        |

---

## API Reference

```go
type Kind int
const (
    KindService Kind = iota + 1
    KindProcess
    KindScheduledTask
)
func (k Kind) String() string

type Opportunity struct {
    Kind        Kind
    ID          string   // ServiceName / PID / TaskPath
    DisplayName string
    BinaryPath  string
    SearchDir   string
    Writable    bool
    Reason      string
}

// ScanServices enumerates Windows services with a writable binary dir.
// Windows only; cross-platform stub returns an error.
func ScanServices() ([]Opportunity, error)

// ParseBinaryPath extracts the exe from an SCM BinaryPathName. Pure
// string parsing, cross-platform.
func ParseBinaryPath(cmdline string) string
```
