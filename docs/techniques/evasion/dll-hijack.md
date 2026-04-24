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
        fmt.Printf("  binary       : %s\n", o.BinaryPath)
        fmt.Printf("  hijacked DLL : %s\n", o.HijackedDLL)
        fmt.Printf("  drop at      : %s\n", o.HijackedPath)
        fmt.Printf("  legit at     : %s\n\n", o.ResolvedDLL)
    }
}
```

Sample output on a Win10 host running as admin (`uhssvc` = Microsoft
Update Health Service, binary in `C:\Program Files\Microsoft Update
Health Tools\`):

```
uhssvc (Microsoft Update Health Service)
  binary       : C:\Program Files\Microsoft Update Health Tools\uhssvc.exe
  hijacked DLL : WINHTTP.dll
  drop at      : C:\Program Files\Microsoft Update Health Tools\WINHTTP.dll
  legit at     : C:\Windows\system32\WINHTTP.dll
```

### Low-level helpers

`SearchOrder(exeDir)` returns the ordered directory list Windows walks
for a DLL load (app dir → System32 → SysWOW64 → Windows).
`HijackPath(exeDir, dllName)` returns the first writable dir in that
order that doesn't already contain the DLL, or `""` if there's no
opportunity (including KnownDLL cases).

### Parsing `BinaryPathName` manually

`ParseBinaryPath` is exported for callers that read service config from
sources other than the SCM (registry dumps, event log exports):

```go
exe := dllhijack.ParseBinaryPath(`"C:\Program Files\Svc\svc.exe" --service`)
// exe == `C:\Program Files\Svc\svc.exe`
```

---

## Composing with `stealthopen.Opener`

Every scanner (`ScanServices`, `ScanProcesses`, `ScanScheduledTasks`,
`ScanAutoElevate`, `ScanAll`) accepts an optional trailing `ScanOpts`
variadic that can route every PE file read through a
`stealthopen.Opener`. Path-keyed EDR file hooks then only see the
volume-root handle, not the victim binary's path.

```go
import (
    "github.com/oioio-space/maldev/evasion/dllhijack"
    "github.com/oioio-space/maldev/evasion/stealthopen"
)

opener, _ := stealthopen.NewStealth(`C:\`)
defer opener.Close()

opps, err := dllhijack.ScanAll(dllhijack.ScanOpts{Opener: opener})
```

`ScanProcesses` accepts `ScanOpts` too, but the Opener is unused there —
it reads live loaded-module lists via Toolhelp32, not PE files from
disk, so there's no file-read surface to reroute. `Validate`'s canary
drop and marker poll are also not reroutable today (writes; future
work).

The `*wsyscall.Caller` pattern does not apply: `dllhijack` doesn't
make `NtXxx` calls — all kernel interaction goes through typed `windows.*`
wrappers + `svc/mgr` + COM `ITaskService`, and PE parsing is pure Go.

## Validating an Opportunity with a canary DLL

`dllhijack.Validate` confirms exploitability end-to-end: drop a canary
DLL at the Opportunity's `HijackedPath`, trigger the victim (service
restart / scheduled task run), poll for a marker file the canary's
`DllMain` creates on load, then clean up.

```go
bytes, _ := os.ReadFile("canary.dll")
result, err := dllhijack.Validate(opp, bytes, dllhijack.ValidateOpts{
    Timeout: 15 * time.Second,
})
if err != nil { log.Fatal(err) }
fmt.Printf("dropped=%v triggered=%v confirmed=%v marker=%s\n",
    result.Dropped, result.Triggered, result.Confirmed, result.MarkerPath)
```

Ship your own canary: see
[`evasion/dllhijack/canary/README.md`](../../../evasion/dllhijack/canary/README.md)
for the 30-line C source (`DllMain` writes a marker file in
`%ProgramData%` and returns TRUE) and MinGW/MSVC build commands. A
pre-built canary is not shipped so each operator's PE has a unique hash.

## Limitations

- **Services + scheduled tasks analyze STATIC imports** (PE import table).
  DLLs loaded at runtime via `LoadLibrary` / `GetModuleHandle` are invisible
  there. `ScanProcesses` covers the runtime-load blind spot by reading the
  live loaded-module list from every accessible process.
- **KindProcess Validate unsupported** — triggering a DLL reload in a
  running process requires killing + relaunching it, which is out of
  scope (too destructive for a reconnaissance helper).

---

## Comparison

| Tool                  | Canary validation | Processes | Services | Tasks    | AutoElevate (UAC) | Scoring | Go-native |
|-----------------------|-------------------|-----------|----------|----------|-------------------|---------|-----------|
| `maldev/dllhijack`    | **yes**           | **yes**   | **yes**  | **yes**  | **yes**           | **yes** | yes       |
| DLLHijackHunter (.NET)| yes               | yes       | yes      | yes      | yes               | partial | no        |
| Siofra (Koret)        | no                | yes       | no       | no       | no                | no      | no        |

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
    Kind         Kind
    ID           string // ServiceName / PID / TaskPath
    DisplayName  string
    BinaryPath   string // the exe that loads DLLs
    HijackedDLL  string // e.g. "version.dll" — the import that would be hijacked
    HijackedPath string // exact drop path for the payload
    ResolvedDLL  string // where the DLL currently resolves (usually System32)
    SearchDir    string // dirname(HijackedPath)
    Writable     bool
    Reason       string
}

// ScanOpts composes scanner-wide options. Pass to any Scan* function
// (variadic: zero or one). Zero value preserves default behaviour.
type ScanOpts struct {
    Opener stealthopen.Opener // optional; path-stealth PE reads
}

// ScanServices enumerates services; per-import PE analysis.
func ScanServices(opts ...ScanOpts) ([]Opportunity, error)

// ScanProcesses enumerates every accessible running process and reads
// its LIVE loaded-module list via Toolhelp32 — covers runtime LoadLibrary.
// Accepts ScanOpts for API symmetry; the Opener is unused (no file reads).
func ScanProcesses(opts ...ScanOpts) ([]Opportunity, error)

// ScanScheduledTasks enumerates registered tasks via COM ITaskService,
// walks each task's exec actions, applies PE-imports filter per binary.
func ScanScheduledTasks(opts ...ScanOpts) ([]Opportunity, error)

// ScanAll = Services ∪ Processes ∪ Tasks ∪ AutoElevate. Partial failures
// are surfaced as a wrapped error but do not abort the remaining scanners.
func ScanAll(opts ...ScanOpts) ([]Opportunity, error)

// SearchOrder returns the DLL search order for a binary in exeDir:
// [exeDir, System32, SysWOW64, Windows]. SafeDllSearchMode is assumed
// on; CWD and %PATH% are deliberately skipped.
func SearchOrder(exeDir string) []string

// HijackPath reports the hijack candidate dir for one (exe, dll) pair:
// the first writable dir earlier in the search order than the DLL's
// real location, or "" if no opportunity. Correctly excludes KnownDLLs.
func HijackPath(exeDir, dllName string) (hijackDir, resolvedDir string)

// Validate drops canaryDLL at opp.HijackedPath, triggers the victim,
// polls for a marker file, and cleans up. Returns a ValidationResult
// describing each stage (Dropped/Triggered/Confirmed/CleanedUp).
func Validate(opp Opportunity, canaryDLL []byte, opts ValidateOpts) (*ValidationResult, error)

// ScanAutoElevate enumerates System32 .exes whose application manifest
// sets autoElevate=true and emits hijack Opportunities via the same
// PE-imports + search-order pipeline. Rows carry AutoElevate=true and
// IntegrityGain=true, feeding into Rank.
func ScanAutoElevate(opts ...ScanOpts) ([]Opportunity, error)

// IsAutoElevate reports whether the PE's embedded manifest flags the
// binary as auto-elevating (<autoElevate>true</autoElevate> or the
// attribute-style autoElevate="true"). Pure byte-level match.
func IsAutoElevate(peBytes []byte) bool

// Rank scores each Opportunity (AutoElevate, IntegrityGain, Kind
// weighting) and returns a new slice sorted by descending Score.
func Rank(opps []Opportunity) []Opportunity

// ScanServices enumerates Windows services with a writable binary dir.
// Windows only; cross-platform stub returns an error.
func ScanServices() ([]Opportunity, error)

// ParseBinaryPath extracts the exe from an SCM BinaryPathName. Pure
// string parsing, cross-platform.
func ParseBinaryPath(cmdline string) string
```
