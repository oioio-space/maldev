---
last_reviewed: 2026-05-06
reflects_commit: c89b877
status: draft
---

# Phase 1f Stage C+D — Go static-PIE reflective loader on Linux

> Design spec locking scope, components, contracts, and tests for
> the Linux side of the maldev packer reflective loader. Closes
> Phase 1f end-to-end for the **operationally-meaningful subset**
> we explicitly target: Go-built static-PIE binaries.
>
> Brainstorming session 2026-05-06 — every choice below is the
> "best, no-laziness, project-philosophy" pick from a 10-question
> dialogue (see Decisions Locked below).

## Summary

| Item | Choice |
|---|---|
| Stages C and D | **Merged** into a single milestone (Stage C alone has zero operational value: symbol resolution without TLS init crashes any libc-using binary at jump time). |
| Target binary scope | **Go static-PIE only** — `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildmode=pie -ldflags='-s -w -extldflags=-static'`. |
| Symbol resolution | **None needed** — Go static-PIE has zero `DT_NEEDED`, zero symbol-bound relocations. Stage B's `R_X86_64_RELATIVE`-only path already covers what these binaries require. |
| TLS init | **Delegated to the Go runtime** — `_rt0_amd64_linux` self-amorces TLS via `arch_prctl(ARCH_SET_FS)`. We never set up TLS ourselves. |
| `Run()` execution | **In-process JMP with Plan 9 asm fake-stack frame** — mirrors the Windows side's "JMP OEP, never returns" contract. |
| Stack frame layout | argc/argv/envp/auxv via `/proc/self/auxv` passthrough (with `AT_RANDOM` overridden by a fresh `crypto/rand` canary). |
| Test fixture | Pre-compiled Go static-PIE checked into `testdata/` + reproducibility Makefile + source `.go`. |

## Decisions locked (10 questions, 10 answers)

1. **Stage scoping** — merge C+D (Q1 answer **B**).
2. **Target scope** — Go static-PIE only (Q2 answer **Z**).
3. **Run() model** — in-process JMP (Q3 answer **P**).
4. **Test fixture** — pre-compiled checked-in (Q4 answer **T1**).
5. **Go detection** — `debug/buildinfo.Read` (improvement **A** over hand-rolled section parser).
6. **Z-scope gate** — at `Prepare()` dispatch, BEFORE `mapAndRelocateELF` (improvement **B**).
7. **Auxv** — passthrough from `/proc/self/auxv`, override `AT_RANDOM` only (improvement **C**).
8. **mmap flags** — `MAP_PRIVATE | MAP_ANONYMOUS` (drop deprecated `MAP_GROWSDOWN`, improvement **D**).
9. **File layout** — single `runtime_linux_amd64.s`, `Run()` body inline in `runtime_linux.go` (improvement **E**).
10. **Pack-time validator** — `packer.ValidateELF` so misuse surfaces before deploy (improvement **F**).

Plus three quality-of-life choices that fell out of brainstorm:
**G** stack 16-byte alignment guard, **H** `-s -w` strip in fixture
build, **I** capture `GoVersion` for diagnostic error messages,
**J** subprocess re-spawn pattern for E2E test.

## Architecture

### Acceptance contract

`Prepare(elf []byte)` accepts ELF input that satisfies **all four**
of the following at gate time:

- `elf` parses as ELF64 LE x86_64 (existing Stage A check).
- `e_type == ET_DYN` (existing Stage B check — ET_EXEC stays
  rejected with `ErrNotImplemented`).
- `debug/buildinfo.Read(bytes.NewReader(elf))` returns no error,
  i.e. `.go.buildinfo` section is present.
- No `DT_NEEDED` entries in `PT_DYNAMIC`, no `PT_INTERP` segment,
  no `PT_TLS` outside what a static-PIE Go runtime declares.

Anything else returns `ErrNotImplemented` with a single,
self-contained operator-facing message:

```
packer/runtime: Linux backend currently supports only Go static-PIE
binaries. Rebuild with:

  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -buildmode=pie -ldflags='-s -w -extldflags=-static' \
    -o <out> <pkg>

(detected: <reason>)
```

### Output contract

`Prepare` returns `*PreparedImage` with:
- `Base` = mmap address of the loaded image (page-aligned)
- `SizeOfImage` = total mapped bytes
- `EntryPoint` = `Base + e_entry` (where Go's `_rt0_amd64_linux` lives)

`PreparedImage.Run()`:
- Gated by `MALDEV_PACKER_RUN_E2E=1`.
- Builds a kernel-style stack frame (argc/argv/envp/auxv).
- JMPs to `EntryPoint` via the Plan 9 asm helper.
- **Never returns.** The Go binary's own runtime takes over;
  it eventually calls `exit_group` which kills the process —
  loader and all.

`PreparedImage.Free()`:
- Unchanged from Stage B (idempotent munmap).
- After a successful `Run()` it's unreachable (process is dead);
  before `Run()` it correctly tears down the mapping.

### File layout

```
pe/packer/
├── packer.go                              # +ValidateELF helper
└── runtime/
    ├── elf.go                              # +isGoStaticPIE, +goVersion, +detectGoStaticPIE
    ├── runtime.go                          # Z-scope gate in Prepare; +CheckLoadable export
    ├── runtime_linux.go                    # Run() body extended (was stub)
    ├── runtime_linux_amd64.s               # NEW — enterEntry asm (Plan 9, NOSPLIT|NOFRAME)
    └── testdata/
        ├── hello_static_pie.go             # NEW — fixture source (~10 LOC)
        ├── hello_static_pie                # NEW — pre-compiled binary (~1.5 MB stripped)
        └── Makefile                        # NEW — reproducible rebuild
```

Constants added to `runtime_linux.go`:

```go
const (
    // fakeStackSize is the size of the kernel-style stack
    // mmap'd by Run() before transferring control. 256 KiB is
    // ample: Go's _rt0_amd64_linux + rt0_go switch to the g0
    // stack within hundreds of bytes of stack use; the rest is
    // headroom for auxv parsing and arch_prctl.
    fakeStackSize = 256 * 1024
)
```

## Components

### `pe/packer/runtime/elf.go` extensions

```go
type elfHeaders struct {
    // ... existing fields ...

    // isGoStaticPIE is true when the ELF satisfies the Z-scope
    // contract: ET_DYN + .go.buildinfo present + no DT_NEEDED +
    // no PT_INTERP. Computed once in parseELFHeaders to avoid a
    // second buffer walk inside the Linux backend.
    isGoStaticPIE bool

    // goVersion is the Go toolchain version that produced the
    // binary (e.g. "go1.21.5"). Populated from
    // debug/buildinfo.Read when isGoStaticPIE is true; empty
    // otherwise. Surfaced in Run() error messages so operators
    // can correlate runtime crashes to toolchain skew.
    goVersion string
}

// detectGoStaticPIE runs the four-condition gate. Called from
// parseELFHeaders after the program-header walk so all the data
// it needs is already parsed. Uses debug/buildinfo from stdlib —
// stable since Go 1.18, future-proof against internal layout
// changes.
func detectGoStaticPIE(elf []byte, h *elfHeaders) (isGo bool, goVersion string) {
    // 1. PT_INTERP / DT_NEEDED checks via h.programs (already parsed)
    // 2. debug/buildinfo.Read(bytes.NewReader(elf)) — primary signal
    // 3. Combine.
}
```

### `pe/packer/runtime/elf.go` — gate helper (cross-platform)

```go
// gateRejectionReason returns the specific failed Z-scope
// condition ("not a Go binary" / "has DT_NEEDED entries: libc.so.6"
// / "has PT_INTERP: /lib64/ld-linux-x86-64.so.2") for diagnostics.
// Returns "" when isGoStaticPIE is true.
func (h *elfHeaders) gateRejectionReason() string { ... }
```

### `pe/packer/runtime/runtime_linux.go` — Z-scope enforcement

The gate fires INSIDE the Linux backend (not in cross-platform
`Prepare`) so non-Linux hosts get the cleaner
`ErrFormatPlatformMismatch` message instead of the gate-specific
"not a Go binary" reason.

```go
func mapAndRelocateELF(elf []byte, h *elfHeaders) (*PreparedImage, error) {
    if !h.isGoStaticPIE {
        return nil, fmt.Errorf("%w: %s", ErrNotImplemented, h.gateRejectionReason())
    }
    // ... existing Stage B mmap + relocs + mprotect ...
}
```

### `pe/packer/runtime/runtime.go` — `CheckELFLoadable` cross-platform export

```go
// CheckELFLoadable returns nil when the bytes form an ELF that
// the Linux runtime would accept (Go static-PIE, ET_DYN, no
// PT_INTERP, no DT_NEEDED), or an error wrapping
// ErrNotImplemented / ErrBadELF / ErrUnsupportedELFArch.
// Pack-time validators use this to reject unsupported binaries
// before deploy. Cross-platform — runs the same check regardless
// of host GOOS, so an operator packing on macOS gets the same
// answer the target Linux loader would.
func CheckELFLoadable(input []byte) error {
    if len(input) < 4 { return ErrBadELF }
    if input[0] != elfMagic0 || input[1] != elfMagic1 ||
        input[2] != elfMagic2 || input[3] != elfMagic3 {
        return fmt.Errorf("%w: not an ELF", ErrBadELF)
    }
    h, err := parseELFHeaders(input)
    if err != nil { return err }
    if h.elfType != etDyn {
        return fmt.Errorf("%w: ET_EXEC not supported (need PIE / ET_DYN)", ErrNotImplemented)
    }
    if !h.isGoStaticPIE {
        return fmt.Errorf("%w: %s", ErrNotImplemented, h.gateRejectionReason())
    }
    return nil
}
```

### `pe/packer/runtime/runtime_linux.go` — `Run()` body

```go
//go:noescape
func enterEntry(entry, stackTop uintptr)

func (p *PreparedImage) Run() error {
    if os.Getenv("MALDEV_PACKER_RUN_E2E") != "1" {
        return errors.New("packer/runtime: PreparedImage.Run requires MALDEV_PACKER_RUN_E2E=1")
    }

    // 1. Allocate fake stack — 256 KiB (fakeStackSize const),
    //    MAP_PRIVATE|MAP_ANONYMOUS. Go runtime switches to its
    //    own g0 stack in rt0_go almost immediately, so 256 KiB
    //    is comfortably above the burn rate of _rt0_amd64_linux
    //    + auxv parsing + arch_prctl. No GROWSDOWN (deprecated
    //    since Linux 5.13).
    stack, err := unix.Mmap(-1, 0, fakeStackSize,
        unix.PROT_READ|unix.PROT_WRITE,
        unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
    if err != nil { return fmt.Errorf("packer/runtime: fake stack mmap: %w", err) }

    // 2. Generate the AT_RANDOM canary (16 bytes from crypto/rand).
    var canary [16]byte
    if _, err := rand.Read(canary[:]); err != nil {
        _ = unix.Munmap(stack)
        return fmt.Errorf("packer/runtime: AT_RANDOM canary: %w", err)
    }

    // 3. Read parent process auxv from /proc/self/auxv. Override
    //    AT_RANDOM with our canary; pass through everything else
    //    (AT_PAGESZ, AT_HWCAP, AT_PLATFORM, AT_SYSINFO_EHDR, ...)
    //    so the loaded Go runtime sees the same host capabilities
    //    a kernel-launched binary would.
    auxv, err := readSelfAuxv(uintptr(unsafe.Pointer(&canary[0])))
    if err != nil {
        _ = unix.Munmap(stack)
        return fmt.Errorf("packer/runtime: read /proc/self/auxv: %w", err)
    }

    // 4. Write argc=0, argv=NULL, envp=NULL, auxv into the top of
    //    the fake stack. Top is stack[fakeStackSize - frameSize].
    //    Frame layout documented inline. Align top to 16 bytes.
    stackTop := writeKernelFrame(stack, auxv)
    stackTop &^= 0xF // 16-byte alignment guard (x86_64 SysV ABI)

    // 5. Hand off to asm. enterEntry never returns.
    enterEntry(p.EntryPoint, stackTop)
    return nil // unreachable
}
```

### `pe/packer/runtime/runtime_linux_amd64.s` — Plan 9 asm

```
TEXT ·enterEntry(SB), NOSPLIT|NOFRAME, $0-16
    // Order matters: FP is computed relative to SP, so we MUST
    // read both args before swapping SP. Once SP is overwritten
    // FP no longer references our caller's frame.
    MOVQ entry+0(FP), AX        // AX = entry point address
    MOVQ stackTop+8(FP), SP     // RSP = top of fake stack
    JMP  AX                     // tail-jump; never returns
```

The Plan 9 asm filename `_linux_amd64.s` enforces GOOS+GOARCH
build constraints implicitly. No `cgo` involved. Symbol naming
follows Go convention (`·enterEntry` resolves to
`runtime.enterEntry` from Go-side `func enterEntry(...)`).

We deliberately do NOT zero registers before JMP. Go's
`_rt0_amd64_linux` re-initializes everything from scratch
(reads SP, calls `runtime·rt0_go`, sets FS via arch_prctl).
Spending instructions on register cleanup would be cargo-cult.

### `pe/packer/packer.go` — `ValidateELF` operator-facing wrapper

```go
// ValidateELF returns nil when `elf` is a Go static-PIE binary
// the Linux runtime can load, or an error explaining why not.
// Thin pass-through to runtime.CheckELFLoadable; lives in the
// packer package so operators can call it without importing the
// runtime sub-package. Call at pack time so misuse surfaces
// before deploy.
func ValidateELF(elf []byte) error {
    return runtime.CheckELFLoadable(elf)
}
```

`cmd/packer pack` calls this automatically and refuses to encrypt
non-loadable inputs (saves a deploy cycle when the operator
forgot a build flag). Programmatic callers can opt out by using
`Pack` directly.

Surface kept narrow: one public function in each package, no
leaked detection internals (`isGoStaticPIE` / `goVersion` stay
unexported on `elfHeaders`).

### `pe/packer/runtime/testdata/`

**`hello_static_pie.go`** (committed source, ~10 LOC):
```go
// Build: see Makefile.
//   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
//     go build -buildmode=pie -ldflags='-s -w -extldflags=-static' \
//     -o hello_static_pie ./hello_static_pie.go
package main

func main() { print("hello from packer\n") }
```

**`hello_static_pie`** (committed binary, ~1.5 MB stripped) — the
pre-compiled fixture. Sits next to its source for audit.

**`Makefile`**:
```makefile
hello_static_pie: hello_static_pie.go
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -buildmode=pie \
		-ldflags='-s -w -extldflags=-static' \
		-o $@ ./$<

clean:
	rm -f hello_static_pie
```

## Data flow

```
operator                    Prepare()                           Run()
   │                            │                                 │
   │ ELF (Go static-PIE)        │                                 │
   ├─────────────────────────►  │                                 │
   │                            ├─ parseELFHeaders                │
   │                            │   ├─ Ehdr + Phdr walk           │
   │                            │   ├─ debug/buildinfo.Read       │
   │                            │   └─ detectGoStaticPIE → yes    │
   │                            ├─ Z-scope gate (Prepare-side)   │
   │                            │   PASS                           │
   │                            ├─ mapAndRelocateELF (Stage B)    │
   │                            │   ├─ mmap PT_LOAD span           │
   │                            │   ├─ copy file bytes             │
   │                            │   ├─ apply RELATIVE relocs       │
   │                            │   ├─ mprotect per segment        │
   │                            │   └─ return PreparedImage        │
   │ ◄──────────────────────────┤                                 │
   │                            │                                 │
   │ PreparedImage.Run()                                          │
   ├──────────────────────────────────────────────────────────────┤
   │                                                              ├─ MALDEV_PACKER_RUN_E2E gate
   │                                                              ├─ mmap fake stack (256 KB)
   │                                                              ├─ rand.Read(canary[16])
   │                                                              ├─ readSelfAuxv (passthrough)
   │                                                              ├─ writeKernelFrame
   │                                                              ├─ align stack top to 16 bytes
   │                                                              ├─ enterEntry(entry, stackTop)
   │                                                              │      ↓ asm
   │                                                              │      RSP := stackTop
   │                                                              │      JMP entry  (no return)
   │                                                              ▼
   │                                            [_rt0_amd64_linux of loaded binary]
   │                                            [reads argc/argv/auxv from new SP]
   │                                            [arch_prctl(ARCH_SET_FS, &tls)]
   │                                            [runtime·rt0_go → main → exit_group(0)]
   ▼
   [process killed — Run() never returned]
```

## Error handling

| Surface | Sentinel | Wrapped message |
|---|---|---|
| Non-Go binary, ET_EXEC, has DT_NEEDED, has PT_INTERP | `ErrNotImplemented` | "Linux backend currently supports only Go static-PIE binaries (need CGO_ENABLED=0 -buildmode=pie -ldflags='-extldflags=-static'); detected: \<reason>" |
| Stage B mmap / mprotect / RELATIVE reloc errors | existing `ErrBadELF` / wrapped `unix.X` | unchanged from Stage B |
| Fake stack mmap fails | wrapped `unix.Mmap` err | "packer/runtime: fake stack mmap: %w" |
| `crypto/rand.Read` fails | wrapped err | "packer/runtime: AT_RANDOM canary: %w" |
| `/proc/self/auxv` open/read fails | wrapped `os.Open` / `io.ReadFull` err | "packer/runtime: read /proc/self/auxv: %w" |
| `Run()` called without env gate | `errors.New` (existing pattern) | "PreparedImage.Run requires MALDEV_PACKER_RUN_E2E=1" |
| `Run()` returned (impossible) | unreachable | unreachable |

**No panics** anywhere on the gate-rejection or Run() pre-jump
paths. Once `enterEntry` is called, the loader has lost control
by design.

## Testing strategy

### Unit tests (always run, never `Run()`)

1. **`TestPrepare_ELF_RejectsNonGo`** — synthetic ELF without
   `.go.buildinfo` section but otherwise valid ET_DYN with PT_LOAD
   + PT_DYNAMIC. Expects `ErrNotImplemented`.

2. **`TestPrepare_ELF_RejectsETExec`** — existing Stage B test;
   continues to pass.

3. **`TestPrepare_ELF_RejectsDTNeeded`** — synthetic Go-marker
   ELF with a DT_NEEDED entry. Expects rejection at gate.
   (Builder needs to support emitting DT_NEEDED + a fake
   `.go.buildinfo` section. Or use the real binary post-modify.)

4. **`TestPrepare_ELF_AcceptsGoStaticPIE`** — `os.ReadFile` of
   `testdata/hello_static_pie`, calls `Prepare`, checks no error
   and `img.Base != 0`, defers `img.Free()`. Does **not** call
   `Run()`. This is the primary mapper smoke test.

5. **`TestPrepare_ELF_DetectGoVersion`** — same fixture; verifies
   `goVersion` is populated (introspected via a small unexported
   getter exposed to the test package). String shape "goX.Y.Z".

6. **`TestRun_GatedByEnvVar_Linux`** — without env, `Run()`
   returns the gate error; existing behavior, kept.

7. **`TestValidateELF_ReportsRejection`** — `packer.ValidateELF`
   on a non-Go binary returns rich error with reason.

### E2E test (gated, opt-in)

8. **`TestRun_GoStaticPIE_E2E`** in `runtime_linux_e2e_test.go`,
   build-tagged `//go:build linux && maldev_packer_run_e2e`.
   Test re-spawns itself as a subprocess via `os/exec.Command`
   with env `MALDEV_PACKER_RUN_E2E=1` + a marker env that routes
   `TestMain` to the inner harness. Inner harness loads the
   fixture, calls `Run()`. Outer captures stdout; asserts
   `"hello from packer"` substring before the subprocess exit.

   ```go
   func TestMain(m *testing.M) {
       if os.Getenv("MALDEV_PACKER_E2E_INNER") == "1" {
           runFixtureAndExit() // calls Prepare + Run; never returns
       }
       os.Exit(m.Run())
   }
   ```

   **Skipped by default**: ungated test runs trip `t.Skip` if the
   marker env isn't set. CI doesn't run it. Operators / contributors
   running locally with `go test -tags=maldev_packer_run_e2e ./pe/packer/runtime/`
   exercise the full path.

### Cross-OS sanity

- All Linux tests guarded `//go:build linux` or `goruntime.GOOS == "linux"` skip.
- `GOOS=windows go build ./pe/packer/runtime/` and `GOOS=darwin go build ...` must continue green (no new symbols leaked into cross-OS scope).

## Future work (out of scope, noted for tracking)

- **Stage E — non-Go static-PIE** (C/Rust binaries with their own
  `_start`) would reuse the same `enterEntry` asm but need
  different gate detection (no `.go.buildinfo`).
- **Stage F — full ld.so emulation** (libc-using ELFs) would
  re-implement chunks of execve. Operationally heavy; defer until
  there's demand evidence.
- **`debug/buildinfo` post-Go-2.x backstop** — if Go ever drops
  `.go.buildinfo`, fall back to detection via `.gopclntab`
  (present since Go 1.0).
- **Repeat the asm-frame trick on the Windows side** — Windows
  Phase 1b currently `syscall.SyscallN(p.EntryPoint)` which
  treats entry as a function call. For real EXEs the kernel-style
  setup would be more correct (TIB, PEB, kernel-style stack).
  Won't crash today (Windows is forgiving) but worth a future
  pass for symmetry.

## See also

- `pe/packer/runtime/doc.go` — package overview, will be bumped on Stage C+D ship.
- `pe/packer/runtime/runtime_linux.go` — Stage B mapper this design extends.
- `docs/refactor-2026-doc/packer-design.md` — phase plan; row 1f gets ✅ on Stage C+D ship.
- `docs/refactor-2026-doc/HANDOFF-2026-05-06.md` — running cross-machine state.
- Go source: `runtime/asm_amd64.s` (`_rt0_amd64_linux`,
  `runtime·rt0_go`) — the entry-point shape we're feeding.
- glibc source: `sysdeps/unix/sysv/linux/x86_64/dl-startup.S` — reference for kernel-style `_start` frame layout.
