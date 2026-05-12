# cmd/privesc-e2e

End-to-end proof of the maldev DLL-hijack privesc chain.

## What it does

Runs from a non-admin shell on the Win10 target. Packs an embedded
probe EXE into a converted DLL via `packer.PackBinary{ConvertEXEtoDLL:
true}`, plants it where a SYSTEM-context scheduled task expects to
find a DLL, triggers the task, and verifies the probe wrote its
elevated `whoami` output to a marker file.

## Layout

| Path | Role |
|---|---|
| `main.go` | Orchestrator (runs as `lowuser`) |
| `probe/probe.c` | Tiny `-nostdlib` C EXE — kernel32-only, writes whoami marker, sleeps. Embedded into orchestrator via `//go:embed probe/probe.exe`. |
| `probe/main.go` | Original Go probe — **does NOT survive** thread-injection by Mode 8 stub (Go runtime requires being the process entry point). Kept as reference; to be revived once we crack the runtime-init issue. |
| `victim/main.go` | DELIBERATELY VULNERABLE — `LoadLibrary("hijackme.dll")`. Deployed by VM provisioning at `C:\Vulnerable\victim.exe`, run as SYSTEM by the scheduled task. |
| `fakelib/fakelib.go` | Real Go-built `c-shared` DLL with three named exports. Embedded into orchestrator via `//go:embed fakelib/fakelib.dll` for Mode 10 path. |

## Build

The orchestrator `//go:embed`s two binaries: `probe/probe.exe`
(C-built) and `fakelib/fakelib.dll` (Go cgo c-shared). Both must
exist on disk before `go build ./cmd/privesc-e2e` succeeds. The
driver `scripts/vm-privesc-e2e.sh` does this in order:

```bash
# 1. probe (C, mingw)
x86_64-w64-mingw32-gcc -nostdlib -e main \
  -o cmd/privesc-e2e/probe/probe.exe \
  cmd/privesc-e2e/probe/probe.c -lkernel32

# 2. fakelib (Go cgo c-shared) — GOTMPDIR avoids host Defender
GOTMPDIR=$(pwd)/ignore/gotmp CGO_ENABLED=1 \
  GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc \
  go build -buildmode=c-shared \
  -o cmd/privesc-e2e/fakelib/fakelib.dll ./cmd/privesc-e2e/fakelib

# 3. orchestrator (embeds both)
GOOS=windows GOARCH=amd64 go build -o privesc-e2e.exe ./cmd/privesc-e2e

# 4. victim (deployed on VM by provisioning script)
GOOS=windows GOARCH=amd64 go build -o victim.exe ./cmd/privesc-e2e/victim
```

Both `probe.exe` and `fakelib.dll` are gitignored — rebuild from
source on each run.

## VM prerequisites (snapshot `INIT-PRIVESC`)

See `scripts/vm-provision-privesc.ps1` (slice 9.1).

- Account `lowuser` (non-admin), SSH-accessible.
- `C:\Vulnerable\` writable by `lowuser`.
- `C:\Vulnerable\victim.exe` deployed (built from `victim/`).
- Scheduled task `MaldevHijackVictim`, action = run victim.exe,
  principal = SYSTEM, with /Run ACL granting `lowuser`.
- Defender exclusions: `C:\Vulnerable\`, `C:\ProgramData\maldev-marker\`.

## Run

```pwsh
# from lowuser shell on the VM
privesc-e2e.exe
```

Exit 0 = SUCCESS (marker shows SYSTEM or another principal).
Exit 1 = FAIL with diagnostics.
