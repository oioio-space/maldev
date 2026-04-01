# maldev — Project Instructions

## Project
Modular malware development library in Go (workspace).
Repo: https://github.com/oioio-space/maldev

## Critical Rules
- The `ignore/` folder MUST NEVER be committed or pushed. Always verify with `git check-ignore -v ignore/` before pushing.
- Always run `go build ./...` in each module before committing.

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
# Windows
go build ./...

# Linux cross-compile
GOOS=linux GOARCH=amd64 go build ./...

# Verify all modules
for mod in core win evasion injection privilege process system pe cleanup c2 cve/CVE-2024-30088; do
  cd $mod && go build ./... && cd ..
done
```

## Module Structure
12 Go modules in workspace (go.work). Dependencies flow bottom-up:
`core/` → `win/` → `evasion/`, `injection/`, `privilege/`, `process/`, `system/`, `pe/`, `cleanup/` → `c2/` → `cve/`
