# maldev — Project Instructions

## Project
Malware development library in Go (single module).
Repo: https://github.com/oioio-space/maldev

## Critical Rules
- The `ignore/` folder MUST NEVER be committed or pushed. Always verify with `git check-ignore -v ignore/` before pushing.
- Always run `go build $(go list ./...)` before committing (excludes `ignore/`).
- Single `go.mod` at root — no workspace, no `go.work`.

## Go Style
Follow the rules in:
- `.claude/skills/go-conventions.md` — naming, packages, files, receivers, anti-chatter, x/sys/windows dedup
- `.claude/skills/go-styleguide.md` — error handling, interfaces, documentation, variable declarations, shadowing

Key rules:
- `camelCase` unexported, `PascalCase` exported. `ID` not `Id`. `HTTP` not `Http`.
- No `utils`, `helpers`, `common` package names.
- Prefer `windows.VirtualAlloc()` over `api.ProcVirtualAlloc.Call()` in new code.
- `%w` at end of `fmt.Errorf`, `%v` at system boundaries.
- Accept interfaces, return concrete types.
- Comments explain WHY, not WHAT.
- Every exported package has a `doc.go` with technique name, MITRE ATT&CK ID, detection level.

## Build
```bash
# Build all (excludes ignore/)
go build $(go list ./...)

# Run tests
go test $(go list ./...)

# Linux cross-compile
GOOS=linux GOARCH=amd64 go build $(go list ./...)

# VM tests (admin/risky tests in isolated VMs)
# Use /vm-test skill or:
./scripts/vm-run-tests.sh windows "./..." "-v -count=1"
./scripts/vm-run-tests.sh linux "./..." "-count=1"
./scripts/vm-run-tests.sh all "./..." "-count=1"
```

## Package Structure
Single module `github.com/oioio-space/maldev`. Dependencies flow bottom-up:

```
Layer 0 (pure):  crypto/  encode/  hash/  random/  useragent/
Layer 1 (OS):    win/api  win/syscall  win/ntapi  win/token  win/privilege  win/version
                 win/domain  win/impersonate  win/user
Layer 2 (tech):  evasion/*  inject/  process/  pe/*  cleanup/*  system/*  uacbypass/
Layer 2 (post):  persistence/*  collection/*
Layer 3 (orch):  c2/transport  c2/shell  c2/meterpreter  c2/cert
Exploits:        exploit/cve202430088
Executables:     cmd/rshell
Internal:        internal/log  internal/compat (slog/cmp/slices polyfills)
Testing:         testutil/
```

## Key Patterns
- `*wsyscall.Caller` as optional parameter (nil = WinAPI fallback) for EDR bypass
- Cross-platform: same package + build tags (`_windows.go` / `_linux.go`)
- Platform-specific techniques: dedicated packages (e.g., `evasion/amsi/` Windows-only)
- `win/api/dll_windows.go` is the single source of truth for DLL handles
