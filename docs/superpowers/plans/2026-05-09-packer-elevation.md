---
last_reviewed: 2026-05-09
reflects_commit: 5834d05
status: in-progress
---

# Packer Elevation — Master Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development
> or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Elevate the maldev packer from "functional" to "reference-quality
pedagogical work" — push binary-size limits, ship the symmetric
attacker/defender pair, and produce visually striking introspection tools.

**Architecture:** Three composable elevations on top of the v0.67.1 baseline:

  1. **Reflective bundle launcher** — in-process loading via existing
     `pe/packer/runtime`. Eliminates the `memfd+execve` double-exec; process
     tree shows one binary, no /proc/self/maps payload trace.

  2. **All-asm bundle stub** — replace the ~5 MB Go launcher with a hand-rolled
     ~200-byte asm stub wrapped in a minimal hand-written ELF/PE container.
     Total bundled binary drops from 5 MB → ~2 KB. Each byte has documented
     intent.

  3. **packer-vis introspection tool** — terminal-art CLI that animates
     each transformation stage: entropy heatmaps, byte-diff between SGN
     rounds, bundle wire-format ASCII visualisation, optional gdb-traced
     stub execution capturing register state at each round boundary.

**Tech Stack:** pure Go, golang-asm, x/sys (linux/windows), bubbletea +
lipgloss for the visual layer. No cgo. Cross-compile-clean for
linux/windows/darwin amd64.

---

## Progress tracker (updated at every milestone — pull from origin/master to resume)

| Phase | Stage | Status | Commit | Tag |
|-------|-------|--------|--------|-----|
| 1 — Reflective launcher | 1.1 Investigate runtime API surface | ✅ | 5834d05 | — |
| 1 — Reflective launcher | 1.2 Add reflective dispatch (`MALDEV_REFLECTIVE=1`) | ✅ | 4d15ad2 | — |
| 1 — Reflective launcher | 1.3 E2E test (linux) | ✅ | 4d15ad2 | — |
| 1 — Reflective launcher | 1.4 Tag v0.68.0 | ✅ | — | **v0.68.0** |
| 2 — All-asm stub | 2.1 Minimal ELF64 writer | ✅ | 69543cd | — |
| 2 — All-asm stub | 2.2 Bundle stub asm — always-idx-0 baseline | ✅ | ddc2d56 | — |
| 2 — All-asm stub | 2.3 Bundle stub container glue (`WrapBundleAsExecutableLinux`) | ✅ | ddc2d56 | — |
| 2 — All-asm stub | 2.4 E2E linux + size assertion (< 4 KiB target — actual 318 B) | ✅ | ddc2d56 | — |
| 2 — All-asm stub | 2.5 Tag v0.69.0 | ✅ | — | **v0.69.0** |
| 2 — All-asm stub | 2.6 Bundle stub asm — scan loop (PT_MATCH_ALL only) | ✅ | c0b58ce | **v0.71.0** |
| 2 — All-asm stub | 2.7 Bundle stub asm — vendor-aware dispatch | ✅ | 873f365 | **v0.72.0** |
| 2 — All-asm stub | 2.8 Minimal PE32+ writer (Windows symmetry) | ⏳ | | |
| 2 — All-asm stub | 2.9 PT_WIN_BUILD predicate in Windows stub | ⏳ | | |
| 3 — packer-vis | 3.1 Entropy heatmap rendering | ✅ | eab7429 | — |
| 3 — packer-vis | 3.3 Bundle wire-format viz | ✅ | eab7429 | — |
| 3 — packer-vis | 3.2 SGN round byte-diff display (deferred — needs hooks in poly engine) | ⏳ | | |
| 3 — packer-vis | 3.4 Tag v0.70.0 | ✅ | — | **v0.70.0** |
| 3 — packer-vis | 3.5 `compare` verb — side-by-side entropy + delta | ✅ | 764a29e | — |
| 4 — Kerckhoffs | 4.1 Library: BundleProfile + 7 *With variants | ✅ | 6072eb4 | — |
| 4 — Kerckhoffs | 4.2 Launcher + CLI: -secret end-to-end | ✅ | 3f61fb2 | **v0.73.0** |
| 4 — Kerckhoffs | 4.3 All-asm WrapBundleAsExecutableLinuxWith | ✅ | 2c2a5c2 | — |
| 5 — Polymorphism | 5.1 Intel multi-byte NOP injection in stub (per pack random) | ✅ | 655ccff | **v0.74.0** |
| 5 — Polymorphism | 5.2 Negate flag in stub asm | ⏳ (Go-side covered; closes spec gap) | | |
| 6 — Defender pair | 6.1 cmd/packerscope — detect/dump/extract | ✅ | f233c26 | **v0.75.0** |
| 7 — Pedagogy | 7.1 Elevation tour worked example | ✅ | df2de82 | — |
| 7 — Pedagogy | 7.2 README PE-row refresh | ✅ | 45a5dbc | — |
| 7 — Pedagogy | 7.3 `make packer-demo` operator playground | ✅ | ec57c80 | — |

**To resume on another machine:**

```bash
git pull origin master
cat docs/superpowers/plans/2026-05-09-packer-elevation.md   # this file
git log --oneline -20                                       # recent commits
```

The `## Resumption notes` section at the bottom captures any in-flight
context that can't be inferred from git log alone.

---

## Phase 1 — Reflective bundle launcher

**Goal:** Replace the launcher's `memfd_create + execve` with in-process
loading via the existing `pe/packer/runtime.Prepare(input)` API.

### File structure

- Create: `cmd/bundle-launcher/exec_reflective_linux.go` — `executePayloadReflective`
  variant calling `runtime.Prepare(payload)` + `(*PreparedImage).Run()`.
- Modify: `cmd/bundle-launcher/main.go` — add `MALDEV_REFLECTIVE=1` env or
  build-tag to dispatch to the reflective path.
- Add: E2E test `cmd/bundle-launcher/launcher_reflective_e2e_linux_test.go`.

### Steps

- [ ] **Step 1.1: Read and understand `pe/packer/runtime.Prepare` contract**

Run:
```bash
grep -A20 "^func Prepare\|^func.*PreparedImage.*Run" \
  pe/packer/runtime/runtime.go pe/packer/runtime/runtime_linux.go \
  | head -60
```
Expected: `Prepare(input []byte)` returns `*PreparedImage` after
parsing+mapping ELF/PE; `(*PreparedImage).Run() error` enters the entry
point.

- [ ] **Step 1.2: Wire reflective path under build tag**

Touch `cmd/bundle-launcher/exec_reflective_linux.go`:
```go
//go:build linux

package main

import (
    "github.com/oioio-space/maldev/pe/packer/runtime"
)

// executePayloadReflective loads payload in-process via the existing
// pe/packer/runtime ELF mapper + entry-point trampoline. Returns the
// PreparedImage's Run error. Process tree shows one binary; no
// /proc/self/maps file path for the payload.
func executePayloadReflective(payload []byte, _ []string) error {
    img, err := runtime.Prepare(payload)
    if err != nil { return err }
    return img.Run()
}
```

- [ ] **Step 1.3: Dispatch knob in main**

Modify `main.go`:
```go
if os.Getenv("MALDEV_REFLECTIVE") == "1" {
    err = executePayloadReflective(plain, os.Args[1:])
} else {
    err = executePayload(plain, os.Args[1:])
}
```

- [ ] **Step 1.4: E2E test**

Create `launcher_reflective_e2e_linux_test.go` mirroring
`TestLauncher_E2E_WrapAndRun` but setting `MALDEV_REFLECTIVE=1`. Use the
`hello_static_pie` fixture from `pe/packer/runtime/testdata/`.

- [ ] **Step 1.5: Commit + push + tag v0.68.0**

```
feat(bundle-launcher): in-process reflective loading via runtime.Prepare
…
```

---

## Phase 2 — All-asm bundle stub

**Goal:** Bundled executable size 5 MB → ~2 KB. Hand-rolled stub +
hand-written ELF/PE.

### Sub-architecture

The stub asm flow:
```
entry:
  call .here ; pop r15           ; r15 = our own RIP (PIC)
  ; bundle is concat'd after stub bytes, so bundle base = r15 + stub_len
  lea rdi, [r15 + STUB_LEN_TO_BUNDLE]  ; rdi = bundle base

  ; Fingerprint match — call into composed primitives
  ; (CPUIDVendorRead, PEBBuildRead, evaluator loop)

  ; On match (idx in eax):
  ;   - decrypt PayloadEntry[eax] in-place
  ;   - JMP to data start
  ;
  ; On no-match: exit syscall (Linux: 60; Windows: ExitProcess)
```

### File structure

- Create: `pe/packer/stubgen/stage1/bundle_evaluator.go` — `EmitBundleEvaluator(b)`:
  hand-encoded loop over the fingerprint table, composing the existing
  primitives.
- Create: `pe/packer/transform/elf_minimal.go` — `BuildMinimalELF(stub, payload []byte) ([]byte, error)`:
  hand-writes ELF64 header + 1 PT_LOAD + .text section.
- Create: `pe/packer/transform/pe_minimal.go` — same for PE32+.
- Create: `pe/packer/bundle_stub.go` — `WrapBundleAsExecutable(bundle []byte, format Format) ([]byte, error)`:
  emits stub via stubgen, wraps via the minimal writers.
- Add: E2E `pe/packer/bundle_stub_e2e_linux_test.go` asserting
  `len(out) < 4096` and exit-code-42 round-trip.

### Steps (high-level — detailed when starting Phase 2)

- [ ] **Step 2.1**: bundle-evaluator asm (with byte-shape test)
- [ ] **Step 2.2**: minimal ELF writer + tests
- [ ] **Step 2.3**: minimal PE writer + tests
- [ ] **Step 2.4**: WrapBundleAsExecutable composing all of the above
- [ ] **Step 2.5**: E2E linux: `exit 42` shellcode payload, assert
      `len(wrapped) < 4 KiB`
- [ ] **Step 2.6**: Tag v0.69.0

---

## Phase 3 — packer-vis

**Goal:** Visual storytelling. Operator types `packer-vis pack notepad.exe`
and watches the .text bytes get encrypted, compressed, polymorphically
masked.

### File structure

- Create: `cmd/packer-vis/main.go` — bubbletea TUI
- Create: `cmd/packer-vis/entropy.go` — Shannon entropy heatmap
  (256-byte windows, 8 brightness levels via Unicode shading
  ░▒▓█)
- Create: `cmd/packer-vis/diff.go` — byte-diff display, two-column
  hex with colored runs
- Create: `cmd/packer-vis/bundle.go` — ASCII art rendering of bundle
  wire format
- Add: README with screen recordings (asciinema)

### Steps

- [ ] **Step 3.1**: skeleton bubbletea app, render entropy heatmap of any
      input file
- [ ] **Step 3.2**: per-round SGN diff display
- [ ] **Step 3.3**: bundle wire-format ASCII viz (boxes with offsets/sizes)
- [ ] **Step 3.4**: README + asciinema demos
- [ ] **Step 3.5**: Tag v0.70.0

---

## Resumption notes

— Phases 1-7 effectively complete on Linux x86-64. Eight tags shipped
  (v0.68.0 → v0.75.0). Open work (all non-blocking):

  - **Stage 2.8** Minimal PE32+ writer — port BuildMinimalELF64 to
    PE32+ for Windows symmetry. Without a Windows VM the runtime
    exercise is limited to `debug/pe` roundtrip; full E2E queue-d
    until VM time.
  - **Stage 2.9** PT_WIN_BUILD predicate in stub — needs the Windows
    stub variant first (depends on 2.8). The host-side primitive
    `EmitPEBBuildRead` already exists in `pe/packer/stubgen/stage1`.
  - **Stage 3.2** packer-vis SGN-diff view — needs hooks in
    `pe/packer/stubgen/poly` to expose intermediate states.
  - **Stage 5.2** Negate flag in stub asm — Go-side `SelectPayload`
    supports it; the asm scan loop would need its per-entry test
    refactored to compute a single match boolean before XORing the
    negate flag. ~50 bytes of asm restructure, all displacements
    move; risk-bounded by the existing E2E gate suite.

— Repo is in a parfaitement résumable state at every commit.
  `git pull` + read this file to continue.
