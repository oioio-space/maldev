# Phase 1e-B — Linux ELF host Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `host.EmitELF` + `FormatLinuxELF` so `packer.PackBinary` can produce runnable Linux ELF static-PIE outputs alongside the existing Windows EXE outputs.

**Architecture:** 90% pipeline reuse from Phase 1e-A (`amd64.Builder` + `poly.Engine` + `stage1.Round.Emit` are OS-agnostic). New: ELF host emitter (mirror of `host.EmitPE`) + Linux Go static-PIE stage-2 binary (rebuilt from the existing cross-platform `stage2_main.go`) + `HostFormat` dispatch in `stubgen` + `FormatLinuxELF` constant in `pe/packer`.

**Tech Stack:** Go 1.21, `debug/elf` (stdlib, read-only — used in tests for parse-back validation), reuse of `github.com/twitchyliquid64/golang-asm` already in deps.

**Source spec:** `docs/superpowers/specs/2026-05-07-phase-1e-b-linux-elf-host-design.md` (commit `1b49d49`).

**Reference for patterns:** Phase 1e-A's plan at `docs/superpowers/plans/2026-05-07-phase-1e-a-implementation.md` (executed in commits `10a060e..7ac90de`, tag `v0.59.0`). Phase 1f Stage E at `pe/packer/runtime/runtime_linux.go` defines the ELF gate the generated binaries must pass.

**Scope check:** Single subsystem (Linux ELF host). 6 tasks.

---

## File Structure

| File | Status | Responsibility |
|---|---|---|
| `pe/packer/stubgen/host/doc.go` | modify | mention both PE + ELF formats |
| `pe/packer/stubgen/host/elf.go` | **create** | `EmitELF`, `ELFConfig`, `ErrEmptyStage1ELF`, `ErrEmptyPayloadELF` |
| `pe/packer/stubgen/host/elf_test.go` | **create** | `debug/elf.NewFile` parse-back + reject-empty tests |
| `pe/packer/stubgen/stubvariants/Makefile` | modify | add `stage2_linux_v01` target |
| `pe/packer/stubgen/stubvariants/stage2_linux_v01` | **create** | committed Linux Go static-PIE binary (~5 MB) |
| `pe/packer/stubgen/stubvariants/README.md` | modify | document Linux variant + sentinel format |
| `pe/packer/stubgen/stubgen.go` | modify | `HostFormat` enum, format-aware `PickStage2Variant` + `Generate` dispatch, `ErrUnsupportedHostFormat` sentinel, embed Linux binary |
| `pe/packer/stubgen/stubgen_test.go` | modify | add ELF Generate + PickStage2Variant cases |
| `pe/packer/packer.go` | modify | `FormatLinuxELF` const + `PackBinary` Linux dispatch |
| `pe/packer/packer_test.go` | modify | `TestPackBinary_LinuxELF_ProducesParsableELF` |
| `cmd/packer/main.go` | modify | accept `-format=linux-elf`, route to PackBinary |
| `pe/packer/runtime/doc.go` | modify | mention Phase 1e-B end-to-end Linux output |
| `docs/refactor-2026-doc/packer-design.md` | modify | phase row → Stages A+B ✅ |
| `docs/refactor-2026-doc/HANDOFF-2026-05-06.md` | modify | "Phase 1e-B shipped" section + Track 3 row |

---

## Task 1: `host.EmitELF` minimal ELF64 static-PIE emitter

**Why first:** Independent of all other work — pure-Go ELF byte emission. The encoder + poly + stage1 work is reused unchanged from 1e-A; only the wrapping format changes.

**Files:**
- Create: `pe/packer/stubgen/host/elf.go`
- Create: `pe/packer/stubgen/host/elf_test.go`
- Modify: `pe/packer/stubgen/host/doc.go`

- [ ] **Step 1.1: Update host/doc.go to mention both formats**

Read current `pe/packer/stubgen/host/doc.go` first. Replace the package overview to mention both PE32+ (existing) and ELF64 static-PIE (this task).

```go
// Package host emits the host binaries that wrap stage-1 polymorphic
// asm bytes + encoded stage-2 + payload blobs.
//
// Two formats today:
//   - EmitPE — Windows PE32+ executable (Phase 1e-A)
//   - EmitELF — Linux ELF64 LE x86_64 static-PIE (Phase 1e-B)
//
// Both are hand-emitted from raw bytes — no debug/* (read-only),
// no external linker. References:
//   - Microsoft PE/COFF Specification Rev 12.0 (PE)
//   - System V ABI AMD64 Architecture Processor Supplement Rev 1.0 (ELF)
//
// # Detection level
//
// N/A — pack-time only. The emitted hosts are loud at runtime
// (highly observable as freshly-allocated RWX'd images); pair
// with evasion/sleepmask + evasion/preset for memory cover.
package host
```

- [ ] **Step 1.2: Write the failing test for EmitELF**

Create `pe/packer/stubgen/host/elf_test.go`:

```go
package host_test

import (
	"bytes"
	"debug/elf"
	"errors"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/stubgen/host"
)

func TestEmitELF_ParsesBackCleanly(t *testing.T) {
	stage1 := []byte{0x90, 0x90, 0xC3} // NOP NOP RET — minimal x64 valid code
	payload := bytes.Repeat([]byte{0xAA}, 256)

	out, err := host.EmitELF(host.ELFConfig{
		Stage1Bytes: stage1,
		PayloadBlob: payload,
	})
	if err != nil {
		t.Fatalf("EmitELF: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("EmitELF returned 0 bytes")
	}

	f, err := elf.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/elf rejected the emitted ELF: %v", err)
	}
	defer f.Close()

	if f.FileHeader.Class != elf.ELFCLASS64 {
		t.Errorf("Class = %v, want ELFCLASS64", f.FileHeader.Class)
	}
	if f.FileHeader.Data != elf.ELFDATA2LSB {
		t.Errorf("Data = %v, want ELFDATA2LSB", f.FileHeader.Data)
	}
	if f.FileHeader.Machine != elf.EM_X86_64 {
		t.Errorf("Machine = %v, want EM_X86_64", f.FileHeader.Machine)
	}
	if f.FileHeader.Type != elf.ET_DYN {
		t.Errorf("Type = %v, want ET_DYN (static-PIE)", f.FileHeader.Type)
	}

	// Count PT_LOAD program headers — expect exactly 2 (text + data).
	loadCount := 0
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD {
			loadCount++
		}
	}
	if loadCount != 2 {
		t.Errorf("PT_LOAD count = %d, want 2", loadCount)
	}

	// Entry point must fall within the first PT_LOAD's vaddr range.
	if len(f.Progs) > 0 {
		first := f.Progs[0]
		if f.FileHeader.Entry < first.Vaddr || f.FileHeader.Entry >= first.Vaddr+first.Memsz {
			t.Errorf("Entry %#x not within first PT_LOAD [%#x, %#x)",
				f.FileHeader.Entry, first.Vaddr, first.Vaddr+first.Memsz)
		}
	}
}

func TestEmitELF_RejectsEmptyStage1(t *testing.T) {
	_, err := host.EmitELF(host.ELFConfig{
		Stage1Bytes: nil,
		PayloadBlob: []byte{0xAA},
	})
	if !errors.Is(err, host.ErrEmptyStage1ELF) {
		t.Errorf("got %v, want ErrEmptyStage1ELF", err)
	}
}

func TestEmitELF_RejectsEmptyPayload(t *testing.T) {
	_, err := host.EmitELF(host.ELFConfig{
		Stage1Bytes: []byte{0x90, 0xC3},
		PayloadBlob: nil,
	})
	if !errors.Is(err, host.ErrEmptyPayloadELF) {
		t.Errorf("got %v, want ErrEmptyPayloadELF", err)
	}
}
```

- [ ] **Step 1.3: Run tests to verify they fail**

Run: `go test -count=1 -v ./pe/packer/stubgen/host/ -run TestEmitELF`
Expected: FAIL with `undefined: host.EmitELF` and `undefined: host.ELFConfig`.

- [ ] **Step 1.4: Implement EmitELF**

Create `pe/packer/stubgen/host/elf.go`:

```go
package host

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ELFConfig parameterizes EmitELF.
type ELFConfig struct {
	Stage1Bytes []byte // emitted asm — goes into the PT_LOAD code segment
	PayloadBlob []byte // encoded stage 2 || encrypted payload — goes into the PT_LOAD data segment
}

// Sentinels.
var (
	ErrEmptyStage1ELF  = errors.New("host: Stage1Bytes is empty (ELF)")
	ErrEmptyPayloadELF = errors.New("host: PayloadBlob is empty (ELF)")
)

// ELF64 layout constants (System V ABI AMD64 Rev 1.0).
const (
	elfMagic0      = 0x7F
	elfClass64     = 2
	elfDataLE      = 1
	elfVersion     = 1
	elfOSABISysv   = 0
	eTypeDyn       = 3
	eMachineX86_64 = 62

	ehdrSize    = 64
	phdrSizeELF = 56
	elfPageSize = 0x1000

	elfPF_X = 1
	elfPF_W = 2
	elfPF_R = 4
	ptLoad  = 1
)

// EmitELF emits a 2-PT_LOAD static-PIE ELF64. PT_LOAD #1 (R+E)
// holds stage 1 asm; PT_LOAD #2 (R) holds the encoded payload
// blob. ET_DYN + no PT_DYNAMIC + no PT_INTERP — matches Phase 1f
// Stage E runtime gate.
//
// Layout: Ehdr (64) → 2 × Phdr (56 each, 112 total) → page-aligned
// PT_LOAD bodies. Section header table is omitted (sh_off=0,
// sh_num=0); ELF runtime loaders only need program headers.
func EmitELF(cfg ELFConfig) ([]byte, error) {
	if len(cfg.Stage1Bytes) == 0 {
		return nil, ErrEmptyStage1ELF
	}
	if len(cfg.PayloadBlob) == 0 {
		return nil, ErrEmptyPayloadELF
	}

	const phdrCount = 2
	const phdrTableEnd = ehdrSize + phdrCount*phdrSizeELF // 64 + 112 = 176

	// PT_LOAD #1 (text): page-aligned start AFTER the header+phdrs.
	textOffset := alignUpELF(uint64(phdrTableEnd), elfPageSize)
	textVAddr := textOffset
	textFileSz := uint64(len(cfg.Stage1Bytes))
	textMemSz := textFileSz

	// PT_LOAD #2 (data): page-aligned start AFTER the text segment.
	dataOffset := alignUpELF(textOffset+textFileSz, elfPageSize)
	dataVAddr := dataOffset
	dataFileSz := uint64(len(cfg.PayloadBlob))
	dataMemSz := dataFileSz

	totalSize := dataOffset + dataFileSz
	out := make([]byte, totalSize)

	// e_ident[16]
	out[0] = elfMagic0
	out[1] = 'E'
	out[2] = 'L'
	out[3] = 'F'
	out[4] = elfClass64
	out[5] = elfDataLE
	out[6] = elfVersion
	out[7] = elfOSABISysv
	// out[8..15] padding zeros — make() default

	// Ehdr non-ident fields
	binary.LittleEndian.PutUint16(out[16:18], eTypeDyn)
	binary.LittleEndian.PutUint16(out[18:20], eMachineX86_64)
	binary.LittleEndian.PutUint32(out[20:24], elfVersion)
	binary.LittleEndian.PutUint64(out[24:32], textVAddr) // e_entry → stage 1 start
	binary.LittleEndian.PutUint64(out[32:40], ehdrSize)  // e_phoff → right after Ehdr
	// e_shoff = 0 (offset 40..48 stays zero — no section headers)
	binary.LittleEndian.PutUint32(out[48:52], 0) // e_flags
	binary.LittleEndian.PutUint16(out[52:54], ehdrSize)
	binary.LittleEndian.PutUint16(out[54:56], phdrSizeELF)
	binary.LittleEndian.PutUint16(out[56:58], phdrCount)
	// e_shentsize / e_shnum / e_shstrndx = 0 (offsets 58..64 stay zero)

	// Phdr #1: PT_LOAD (R+E) — text
	writeProgHdr(out[ehdrSize:ehdrSize+phdrSizeELF],
		ptLoad, elfPF_R|elfPF_X,
		textOffset, textVAddr, textVAddr,
		textFileSz, textMemSz, elfPageSize)

	// Phdr #2: PT_LOAD (R) — data (encoded payload blob)
	writeProgHdr(out[ehdrSize+phdrSizeELF:ehdrSize+2*phdrSizeELF],
		ptLoad, elfPF_R,
		dataOffset, dataVAddr, dataVAddr,
		dataFileSz, dataMemSz, elfPageSize)

	// Section bodies
	copy(out[textOffset:], cfg.Stage1Bytes)
	copy(out[dataOffset:], cfg.PayloadBlob)

	return out, nil
}

// writeProgHdr emits one Elf64_Phdr (56 bytes) to dst. Order
// matches sysdeps: p_type, p_flags, p_offset, p_vaddr, p_paddr,
// p_filesz, p_memsz, p_align.
func writeProgHdr(dst []byte, pType uint32, pFlags uint32,
	pOffset, pVAddr, pPAddr, pFileSz, pMemSz, pAlign uint64) {
	if len(dst) < phdrSizeELF {
		panic(fmt.Sprintf("writeProgHdr: dst too small: %d", len(dst)))
	}
	binary.LittleEndian.PutUint32(dst[0:4], pType)
	binary.LittleEndian.PutUint32(dst[4:8], pFlags)
	binary.LittleEndian.PutUint64(dst[8:16], pOffset)
	binary.LittleEndian.PutUint64(dst[16:24], pVAddr)
	binary.LittleEndian.PutUint64(dst[24:32], pPAddr)
	binary.LittleEndian.PutUint64(dst[32:40], pFileSz)
	binary.LittleEndian.PutUint64(dst[40:48], pMemSz)
	binary.LittleEndian.PutUint64(dst[48:56], pAlign)
}

func alignUpELF(v, align uint64) uint64 {
	return (v + align - 1) &^ (align - 1)
}
```

NOTE: the existing `pe.go` already defines `alignUp(uint32, uint32)`. The ELF version is `alignUpELF(uint64, uint64)` to avoid collision; if Go's generic alignUp suits both with type generics, the simplify pass can collapse them.

- [ ] **Step 1.5: Run tests to verify they pass**

Run: `go test -count=1 -v ./pe/packer/stubgen/host/`
Expected: PASS for all tests including the existing PE tests.

- [ ] **Step 1.6: Cross-OS build sanity**

Run:
```bash
GOOS=windows go build ./pe/packer/stubgen/host/
GOOS=darwin go build ./pe/packer/stubgen/host/
go build ./pe/packer/stubgen/host/
```
Expected: all clean.

- [ ] **Step 1.7: /simplify pass on the diff**

Apply findings inline. Likely candidates:
- `alignUpELF` vs `alignUp` — if collapsing into a single generic helper improves readability without complicating the existing `pe.go`, do it. Otherwise keep them distinct (the type difference is real).
- WHAT comments inside `EmitELF` — trim if obvious from code.

- [ ] **Step 1.8: Commit**

```bash
git add pe/packer/stubgen/host/doc.go pe/packer/stubgen/host/elf.go pe/packer/stubgen/host/elf_test.go
git -c user.name=oioio-space -c user.email=oioio-space@users.noreply.github.com commit -m "feat(pe/packer/stubgen/host): EmitELF — minimal ELF64 static-PIE emitter

Hand-emits a 2-PT_LOAD static-PIE ELF64 (ET_DYN + no PT_DYNAMIC +
no PT_INTERP) wrapping stage-1 asm bytes + encoded stage-2/payload
blob. Matches the Phase 1f Stage E runtime gate so the generated
binary is loadable by pe/packer/runtime.LoadPE on Linux.

Layout: Ehdr (64) → 2× Phdr (56 each) → page-aligned PT_LOAD
bodies. Section header table omitted (no debug info / no symbol
table — minimal runnable ELF).

PT_LOAD #1: R+E for stage 1 (entry point = vaddr).
PT_LOAD #2: R for the encoded payload blob.

Tests parse the emitted bytes back via debug/elf.NewFile —
asserts ELFCLASS64, ELFDATA2LSB, EM_X86_64, ET_DYN, exactly 2
PT_LOAD program headers, entry point within first PT_LOAD's
vaddr range. Empty Stage1Bytes / PayloadBlob inputs reject with
ErrEmptyStage1ELF / ErrEmptyPayloadELF.

References: System V ABI AMD64 Rev 1.0 § Program Loading +
Linker Considerations.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

Push:
```bash
git push origin master
```

**Ready to ship as commit when:**
- 3 new tests pass + existing PE tests still pass
- Cross-OS builds clean
- /simplify findings applied

---

## Task 2: stage2_linux_v01 Linux Go static-PIE binary

**Why second:** Independent of Task 1 (it's a build artifact + Makefile delta). Task 3 (`stubgen.go` HostFormat) needs both Task 1 (EmitELF) and Task 2 (committed Linux binary) before it can dispatch.

**Files:**
- Modify: `pe/packer/stubgen/stubvariants/Makefile`
- Create: `pe/packer/stubgen/stubvariants/stage2_linux_v01` (committed binary)
- Modify: `pe/packer/stubgen/stubvariants/README.md`

- [ ] **Step 2.1: Verify the existing stage2_main.go is cross-platform**

Run:
```bash
grep -n "GOOS\|runtime.GOOS" pe/packer/stubgen/stubvariants/stage2_main.go
```

Expected: at most one `runtime.GOOS != "windows"` check that gets removed or relaxed for Linux. If the source contains hard Windows-only logic, it's NOT cross-platform — flag and stop. Per the spec, the source IS expected to be cross-platform.

If `stage2_main.go` has `if runtime.GOOS != "windows" { os.Exit(2) }` (a Phase 1e-A guard), that block must be removed OR generalized to allow Linux. The runtime.LoadPE call on Linux dispatches to mapAndRelocateELF (Phase 1f Stage E), which handles ELF inputs cleanly.

If you find a hard-coded Windows guard, remove it. The runtime.LoadPE / Prepare API works identically on both platforms. Update the source's doc comment to reflect cross-platform support.

- [ ] **Step 2.2: Modify the Makefile to add a Linux target**

Read the current Makefile first. Add a `stage2_linux_v01` target alongside the existing `stage2_v01.exe`:

```makefile
# Reproducible rebuild of the Phase 1e-A/B stage-2 stub variants.
# Run from this directory: `make all` builds both variants.

GO ?= go

# Phase 1e-A: Windows EXE (stage 2 wraps the Windows runtime path)
stage2_v01.exe: stage2_main.go
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
		$(GO) build -trimpath \
		-ldflags='-s -w -buildid=' \
		-o $@ ./$<

# Phase 1e-B: Linux ELF static-PIE (stage 2 wraps the Linux runtime
# path — Phase 1f Stage E). -buildmode=pie produces ET_DYN with the
# right section layout (RELA entries kept; -d would drop them and
# break .data.rel.ro pointers).
stage2_linux_v01: stage2_main.go
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		$(GO) build -trimpath \
		-buildmode=pie \
		-ldflags='-s -w -buildid=' \
		-o $@ ./$<

all: stage2_v01.exe stage2_linux_v01

clean:
	rm -f stage2_v01.exe stage2_linux_v01

.PHONY: all clean
```

- [ ] **Step 2.3: Build the Linux binary**

```bash
cd pe/packer/stubgen/stubvariants && make stage2_linux_v01 && cd -
```

Expected: produces `stage2_linux_v01` binary.

Verify the shape:
```bash
file pe/packer/stubgen/stubvariants/stage2_linux_v01
```

Expected output (substring): `ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, ...stripped` (Go static-PIE on Linux is reported as "dynamically linked" by file because of PT_INTERP, but DT_NEEDED is empty — that's the Phase 1f Stage E pattern).

- [ ] **Step 2.4: Verify the binary passes the runtime gate**

The committed Linux binary must pass `pe/packer/runtime.CheckELFLoadable` so stage 1 → stage 2 hand-off works at runtime.

Write a one-off probe at `/tmp/check_linux_stub.go`:

```go
package main

import (
	"fmt"
	"os"

	"github.com/oioio-space/maldev/pe/packer/runtime"
)

func main() {
	b, err := os.ReadFile("pe/packer/stubgen/stubvariants/stage2_linux_v01")
	if err != nil {
		panic(err)
	}
	if err := runtime.CheckELFLoadable(b); err != nil {
		fmt.Println("REJECTED:", err)
		os.Exit(1)
	}
	fmt.Println("OK: stage 2 Linux variant passes the runtime gate")
}
```

Run:
```bash
go run /tmp/check_linux_stub.go && rm /tmp/check_linux_stub.go
```
Expected: `OK: stage 2 Linux variant passes the runtime gate`.

If REJECTED, the build flags are wrong — re-check that `-buildmode=pie -ldflags='-s -w'` was used (NOT `-d`). Stage E review confirmed `-d` causes RELA dropping which breaks the runtime.

- [ ] **Step 2.5: Update README.md**

Read the current README. Update to mention both variants. The section listing variants should now read approximately:

```markdown
## Variants

Phase 1e-A and 1e-B together ship 2 variants today:

- `stage2_v01.exe` — Windows PE32+ Go static EXE (Phase 1e-A)
- `stage2_linux_v01` — Linux ELF64 static-PIE (Phase 1e-B)

Future stages will add v02..v08 of each format with:

- Different `-ldflags` settings
- Minor source tweaks (junk-only variants of `stage2_main.go`)
- Different Go toolchain versions in the maintainer's pinned set

The packer picks variant `seed % len(committed_variants)` per pack
to add a stage-2 byte-uniqueness axis on top of stage-1's per-pack
polymorphism.

## Building

```bash
cd pe/packer/stubgen/stubvariants/
make all  # builds both stage2_v01.exe + stage2_linux_v01
```

Requires `go` on `PATH`. Build flags pin `-trimpath -s -w
-buildid=''` for byte-stability across CI runs. Linux variant
adds `-buildmode=pie`.
```

(Keep the existing sentinel format documentation — it's unchanged.)

- [ ] **Step 2.6: Force-add the Linux binary**

The repo's root `.gitignore` filters `*.exe` and may filter other extensionless executables. Force-add the Linux binary:

```bash
git add -f pe/packer/stubgen/stubvariants/stage2_linux_v01
git status pe/packer/stubgen/stubvariants/stage2_linux_v01
```

Expected: shows `new file: ...stage2_linux_v01` in the staged set.

- [ ] **Step 2.7: /simplify pass on the diff**

The Makefile and README diffs are mostly mechanical. /simplify focuses on:
- Are the build commands consistent across PE and ELF targets (same flag philosophy)?
- Does the README accurately describe the new artifact?

- [ ] **Step 2.8: Commit**

```bash
git add pe/packer/stubgen/stubvariants/Makefile pe/packer/stubgen/stubvariants/README.md
# stage2_linux_v01 already staged via -f in step 2.6
git -c user.name=oioio-space -c user.email=oioio-space@users.noreply.github.com commit -m "feat(pe/packer/stubgen/stubvariants): stage2_linux_v01 Linux Go static-PIE

Phase 1e-B stage 2: rebuild of the existing cross-platform
stage2_main.go for GOOS=linux GOARCH=amd64 -buildmode=pie.
Produces an ET_DYN static-PIE binary that passes Phase 1f
Stage E's runtime gate (no DT_NEEDED, retains RELA for
.data.rel.ro pointer fixup).

At runtime the Linux variant follows the same flow as the
Windows EXE variant:
  1. os.Executable + bytes.Index sentinel locates the trailer
  2. Read u64 payloadLen + u64 keyLen + payload + key
  3. runtime.LoadPE(payload, key) → JMP to original OEP
     via Phase 1f Stage C+D's fake stack frame.

Makefile gains a stage2_linux_v01 target alongside
stage2_v01.exe; 'make all' builds both. Build flags pin
-trimpath -s -w -buildid='' for byte-stability; Linux adds
-buildmode=pie.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

Push:
```bash
git push origin master
```

**Ready to ship as commit when:**
- `make stage2_linux_v01` succeeds locally
- `file` output reports ELF 64-bit static-PIE
- `runtime.CheckELFLoadable` accepts the binary
- Binary committed via `git add -f`
- Cross-OS builds for the rest of the module remain clean

---

## Task 3: stubgen.go HostFormat enum + format-aware Generate / PickStage2Variant

**Why third:** Wires Tasks 1+2 together. Generate's caller (Task 4's PackBinary) needs the HostFormat dispatch.

**Files:**
- Modify: `pe/packer/stubgen/stubgen.go`
- Modify: `pe/packer/stubgen/stubgen_test.go`

- [ ] **Step 3.1: Read existing stubgen.go to identify modification points**

Run: `cat pe/packer/stubgen/stubgen.go`. Identify:
- The current `Options` struct
- The current `PickStage2Variant(seed int64)` signature
- The current `Generate(opts Options)` flow ending in `host.EmitPE`
- The `//go:embed stubvariants/stage2_v01.exe` directive

These all need updating.

- [ ] **Step 3.2: Add HostFormat enum + ErrUnsupportedHostFormat sentinel**

Add to `stubgen.go` (near the existing sentinels):

```go
// HostFormat selects which output format Generate produces.
type HostFormat uint8

const (
	HostFormatPE  HostFormat = 0 // Windows PE32+ (Phase 1e-A; default for backwards compat)
	HostFormatELF HostFormat = 1 // Linux ELF64 static-PIE (Phase 1e-B)
)

// String returns the canonical lowercase format name.
func (h HostFormat) String() string {
	switch h {
	case HostFormatPE:
		return "pe"
	case HostFormatELF:
		return "elf"
	default:
		return fmt.Sprintf("hostformat(%d)", uint8(h))
	}
}

// ErrUnsupportedHostFormat fires when Generate / PickStage2Variant
// receives an unknown HostFormat value.
var ErrUnsupportedHostFormat = errors.New("stubgen: unsupported host format")
```

- [ ] **Step 3.3: Add the HostFormat field to Options**

Modify the `Options` struct definition. Add `HostFormat` field at the end (so existing zero-value callers default to `HostFormatPE` and 1e-A behavior is preserved):

```go
type Options struct {
	Inner      []byte
	Rounds     int
	Seed       int64
	HostFormat HostFormat // NEW: 0 (PE) is the default for backwards compat
}
```

- [ ] **Step 3.4: Embed the Linux binary alongside the PE one**

Add a second go:embed directive:

```go
//go:embed stubvariants/stage2_v01.exe
var stage2V01PE []byte

//go:embed stubvariants/stage2_linux_v01
var stage2V01ELF []byte
```

The existing `stage2V01` variable name (if present) should be renamed to `stage2V01PE` for symmetry. Update all internal references.

- [ ] **Step 3.5: Update PickStage2Variant signature**

The current signature is `PickStage2Variant(seed int64) ([]byte, error)`. Change to format-aware:

```go
// PickStage2Variant returns one of the committed stage-2 binaries
// for the requested format, chosen deterministically from seed.
func PickStage2Variant(seed int64, format HostFormat) ([]byte, error) {
	switch format {
	case HostFormatPE:
		return stage2V01PE, nil
	case HostFormatELF:
		return stage2V01ELF, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedHostFormat, format)
	}
}
```

If the existing function had a `[][]byte` slice + `seed % len()` modulo for variant selection, keep that pattern: replace the single slice with two slices indexed by HostFormat. With one variant per format today, the modulo collapses to "always variant 0", which is fine.

- [ ] **Step 3.6: Update Generate to dispatch on HostFormat**

Find the current `Generate` body. The closing call to `host.EmitPE(...)` becomes:

```go
	switch opts.HostFormat {
	case HostFormatPE:
		out, err := host.EmitPE(host.PEConfig{
			Stage1Bytes: stage1Bytes,
			PayloadBlob: encoded,
		})
		if err != nil {
			return nil, fmt.Errorf("stubgen: host.EmitPE: %w", err)
		}
		return out, nil
	case HostFormatELF:
		out, err := host.EmitELF(host.ELFConfig{
			Stage1Bytes: stage1Bytes,
			PayloadBlob: encoded,
		})
		if err != nil {
			return nil, fmt.Errorf("stubgen: host.EmitELF: %w", err)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedHostFormat, opts.HostFormat)
	}
```

- [ ] **Step 3.7: Update existing tests for the new PickStage2Variant signature**

Search for all `PickStage2Variant(` callsites in `stubgen_test.go`. Each call must add the format argument. The existing tests called it as `PickStage2Variant(0)` — change to `PickStage2Variant(0, stubgen.HostFormatPE)` to preserve test semantics.

- [ ] **Step 3.8: Add new ELF tests**

Append to `pe/packer/stubgen/stubgen_test.go`:

```go
func TestPickStage2Variant_ELF(t *testing.T) {
	if goruntime.GOOS != "linux" {
		t.Skip("Linux variant test — debug/elf is cross-platform but the build flags assume Linux toolchain reachability")
	}
	stage2, err := stubgen.PickStage2Variant(0, stubgen.HostFormatELF)
	if err != nil {
		t.Fatalf("PickStage2Variant ELF: %v", err)
	}
	if len(stage2) == 0 {
		t.Fatal("Linux stage-2 variant is empty")
	}
	// Parse via debug/elf to confirm the embedded binary is well-formed.
	f, err := elf.NewFile(bytes.NewReader(stage2))
	if err != nil {
		t.Fatalf("debug/elf rejects the embedded Linux variant: %v", err)
	}
	defer f.Close()
	if f.FileHeader.Type != elf.ET_DYN {
		t.Errorf("embedded variant is not ET_DYN: %v", f.FileHeader.Type)
	}
}

func TestPickStage2Variant_RejectsUnknownFormat(t *testing.T) {
	_, err := stubgen.PickStage2Variant(0, stubgen.HostFormat(99))
	if !errors.Is(err, stubgen.ErrUnsupportedHostFormat) {
		t.Errorf("got %v, want ErrUnsupportedHostFormat", err)
	}
}

func TestGenerate_LinuxELF_ProducesParsableELF(t *testing.T) {
	inner := bytes.Repeat([]byte("the quick brown fox "), 100)
	out, err := stubgen.Generate(stubgen.Options{
		Inner:      inner,
		Rounds:     3,
		Seed:       1,
		HostFormat: stubgen.HostFormatELF,
	})
	if err != nil {
		t.Fatalf("Generate ELF: %v", err)
	}
	f, err := elf.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/elf rejected: %v", err)
	}
	defer f.Close()
	loadCount := 0
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD {
			loadCount++
		}
	}
	if loadCount != 2 {
		t.Errorf("PT_LOAD count = %d, want 2", loadCount)
	}
}
```

Add imports `"debug/elf"`, `"bytes"`, `"errors"`, `goruntime "runtime"` if not already present.

- [ ] **Step 3.9: Run tests + cross-OS build**

Run:
```bash
go test -count=1 -v ./pe/packer/stubgen/
GOOS=windows go build ./pe/packer/stubgen/...
GOOS=darwin go build ./pe/packer/stubgen/...
```

Expected: PASS, all builds clean. If `TestGenerate_PerPackUniqueness` (existing) breaks because it didn't specify HostFormat, the default zero-value HostFormatPE preserves PE behavior — should still pass.

- [ ] **Step 3.10: /simplify pass**

Apply findings inline.

- [ ] **Step 3.11: Commit**

```bash
git add pe/packer/stubgen/stubgen.go pe/packer/stubgen/stubgen_test.go
git -c user.name=oioio-space -c user.email=oioio-space@users.noreply.github.com commit -m "feat(pe/packer/stubgen): HostFormat enum — Generate/PickStage2Variant ELF dispatch

Phase 1e-B wiring: stubgen now dispatches between PE32+ (1e-A) and
ELF64 static-PIE (1e-B) hosts based on Options.HostFormat. Default
zero-value is HostFormatPE so all 1e-A callers (including
PackBinary's existing FormatWindowsExe path) keep their behavior
unchanged.

Two go:embed directives (stage2V01PE + stage2V01ELF) carry the
committed binaries from stubvariants/. PickStage2Variant takes a
format param and routes to the right slice. Unknown HostFormat
fires ErrUnsupportedHostFormat at both PickStage2Variant and
Generate boundaries.

Generate's tail dispatches host.EmitPE / host.EmitELF based on
HostFormat — pipeline before that point (encode + stage1 emit
+ amd64 lower) is OS-agnostic and reused unchanged.

Tests:
- TestPickStage2Variant_ELF — debug/elf parses the embedded Linux
  binary, asserts ET_DYN.
- TestPickStage2Variant_RejectsUnknownFormat — sentinel routing.
- TestGenerate_LinuxELF_ProducesParsableELF — full Generate call
  with HostFormatELF, debug/elf parses, 2 PT_LOAD asserted.

Existing PickStage2Variant callsites updated to pass HostFormatPE
explicitly.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"

git push origin master
```

**Ready to ship as commit when:**
- All stubgen tests pass (existing + new ELF cases)
- HostFormat zero-value preserves 1e-A behavior
- Cross-OS builds clean

---

## Task 4: pe/packer.PackBinary FormatLinuxELF case

**Files:**
- Modify: `pe/packer/packer.go`
- Modify: `pe/packer/packer_test.go`

- [ ] **Step 4.1: Add FormatLinuxELF constant + update String**

Modify the existing `Format` block in `pe/packer/packer.go`:

```go
const (
	FormatUnknown    Format = iota
	FormatWindowsExe        // Phase 1e-A
	FormatLinuxELF          // Phase 1e-B
)

func (f Format) String() string {
	switch f {
	case FormatWindowsExe:
		return "windows-exe"
	case FormatLinuxELF:
		return "linux-elf"
	default:
		return fmt.Sprintf("format(%d)", uint8(f))
	}
}
```

- [ ] **Step 4.2: Update PackBinary to dispatch on Format**

Find the existing `PackBinary` function. The validation block currently rejects everything except `FormatWindowsExe`. Replace with format-aware dispatch:

```go
func PackBinary(payload []byte, opts PackBinaryOptions) (host []byte, key []byte, err error) {
	var hostFormat stubgen.HostFormat
	switch opts.Format {
	case FormatWindowsExe:
		hostFormat = stubgen.HostFormatPE
	case FormatLinuxELF:
		hostFormat = stubgen.HostFormatELF
	default:
		return nil, nil, fmt.Errorf("%w: %s", ErrUnsupportedFormat, opts.Format)
	}

	rounds := opts.Stage1Rounds
	if rounds == 0 {
		rounds = 3
	}

	pipeline := opts.Pipeline
	if pipeline == nil {
		pipeline = []PipelineStep{{Op: OpCipher, Algo: uint8(CipherAESGCM)}}
	}
	encryptedPayload, keys, err := PackPipeline(payload, pipeline)
	if err != nil {
		return nil, nil, fmt.Errorf("packer: PackPipeline: %w", err)
	}
	key = keys[0]

	stage2, err := stubgen.PickStage2Variant(opts.Seed, hostFormat)
	if err != nil {
		return nil, nil, fmt.Errorf("packer: %w", err)
	}

	inner, err := stubgen.PatchStage2(stage2, encryptedPayload, key)
	if err != nil {
		return nil, nil, fmt.Errorf("packer: PatchStage2: %w", err)
	}

	host, err = stubgen.Generate(stubgen.Options{
		Inner:      inner,
		Rounds:     rounds,
		Seed:       opts.Seed,
		HostFormat: hostFormat,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("packer: stubgen.Generate: %w", err)
	}

	return host, key, nil
}
```

- [ ] **Step 4.3: Add a Linux ELF test**

Append to `pe/packer/packer_test.go`:

```go
func TestPackBinary_LinuxELF_ProducesParsableELF(t *testing.T) {
	payload := []byte("hello payload")
	out, key, err := packer.PackBinary(payload, packer.PackBinaryOptions{
		Format:       packer.FormatLinuxELF,
		Stage1Rounds: 3,
		Seed:         1,
	})
	if err != nil {
		t.Fatalf("PackBinary Linux: %v", err)
	}
	if len(key) == 0 {
		t.Error("returned key is empty")
	}
	f, err := elf.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/elf rejected: %v", err)
	}
	defer f.Close()
	if f.FileHeader.Type != elf.ET_DYN {
		t.Errorf("Type = %v, want ET_DYN", f.FileHeader.Type)
	}
	if f.FileHeader.Machine != elf.EM_X86_64 {
		t.Errorf("Machine = %v, want EM_X86_64", f.FileHeader.Machine)
	}
}
```

Add `"debug/elf"` import if missing.

- [ ] **Step 4.4: Run tests + cross-OS build**

```bash
go test -count=1 -v ./pe/packer/
GOOS=windows go build ./pe/packer/...
GOOS=darwin go build ./pe/packer/...
go build $(go list ./... | grep -v scripts/x64dbg-harness)
```

Expected: PASS for all, including pre-existing PE tests.

- [ ] **Step 4.5: /simplify pass**

- [ ] **Step 4.6: Commit**

```bash
git add pe/packer/packer.go pe/packer/packer_test.go
git -c user.name=oioio-space -c user.email=oioio-space@users.noreply.github.com commit -m "feat(pe/packer): FormatLinuxELF — operator-facing Phase 1e-B

PackBinary now dispatches on opts.Format:
  FormatWindowsExe → stubgen.HostFormatPE → host.EmitPE
  FormatLinuxELF   → stubgen.HostFormatELF → host.EmitELF

Pipeline / Stage1Rounds / Seed / Key handling unchanged. Default
PipelineStep stays AES-GCM-only for both formats.

Test: PackBinary({Format: FormatLinuxELF}) produces a
debug/elf-parsable ET_DYN x86_64 PIE; key returned non-empty.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"

git push origin master
```

**Ready to ship as commit when:**
- New ELF test passes; existing PE tests still pass
- Whole-module + cross-OS builds clean

---

## Task 5: cmd/packer wire `-format=linux-elf`

**Files:**
- Modify: `cmd/packer/main.go`

- [ ] **Step 5.1: Read the existing runPack flow**

Run: `cat cmd/packer/main.go | head -200` to see how `runPack` currently dispatches on `-format`. Phase 1e-A added `-format=blob` (legacy) and `-format=windows-exe` branches.

- [ ] **Step 5.2: Add the linux-elf branch**

In `runPack`, find the format switch. Add a `case "linux-elf"` that mirrors the `case "windows-exe"` block:

```go
	case "windows-exe":
		hostBytes, key, err := packer.PackBinary(input, packer.PackBinaryOptions{
			Format:       packer.FormatWindowsExe,
			Stage1Rounds: *rounds,
			Seed:         *seed,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "packer: %v\n", err)
			return 1
		}
		if err := os.WriteFile(*out, hostBytes, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "packer: write out: %v\n", err)
			return 1
		}
		fmt.Printf("%x\n", key)

	case "linux-elf":
		hostBytes, key, err := packer.PackBinary(input, packer.PackBinaryOptions{
			Format:       packer.FormatLinuxELF,
			Stage1Rounds: *rounds,
			Seed:         *seed,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "packer: %v\n", err)
			return 1
		}
		if err := os.WriteFile(*out, hostBytes, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "packer: write out: %v\n", err)
			return 1
		}
		fmt.Printf("%x\n", key)
```

If the existing case "windows-exe" is in a helper function (e.g. `runPackWindowsExe`), add a parallel `runPackLinuxELF` function and dispatch to it from the format switch. Mirror whatever structure already exists.

- [ ] **Step 5.3: Update the format flag's help text**

Find the flag declaration:

```go
format := fs.String("format", "blob", `output format: "blob" (legacy) or "windows-exe" (Phase 1e-A)`)
```

Update to:

```go
format := fs.String("format", "blob", `output format: "blob" (legacy: encrypted bytes), "windows-exe" (Phase 1e-A: runnable PE), "linux-elf" (Phase 1e-B: runnable ELF static-PIE)`)
```

- [ ] **Step 5.4: Update the usage() function**

Find `usage()` and update the description of the pack subcommand to mention the new format option.

- [ ] **Step 5.5: Smoke test the CLI**

```bash
go build ./cmd/packer
go run ./cmd/packer pack --help 2>&1 | head -20
```

Expected: usage text shows `-format` with the linux-elf option, no panics.

End-to-end smoke (write a tiny payload, pack it):

```bash
echo -n "hello world" > /tmp/probe.bin
go run ./cmd/packer pack -in /tmp/probe.bin -out /tmp/probe.elf -format linux-elf 2>/tmp/probe.err
echo "stdout key (truncated):"; head -c 16 /tmp/probe.bin && echo
file /tmp/probe.elf
rm -f /tmp/probe.bin /tmp/probe.err /tmp/probe.elf
```

Expected: `file /tmp/probe.elf` reports `ELF 64-bit LSB pie executable, x86-64`. The CLI writes the AEAD key to stdout (hex) as designed.

- [ ] **Step 5.6: /simplify pass**

The PE and ELF dispatch blocks are nearly identical (modulo Format constant and output extension). Consider extracting a small helper if /simplify flags it as duplication:

```go
func runPackBinary(input []byte, format packer.Format, opts packer.PackBinaryOptions, outPath string) int {
	opts.Format = format
	hostBytes, key, err := packer.PackBinary(input, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "packer: %v\n", err)
		return 1
	}
	if err := os.WriteFile(outPath, hostBytes, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "packer: write out: %v\n", err)
		return 1
	}
	fmt.Printf("%x\n", key)
	return 0
}
```

If /simplify says the duplication is small enough not to justify extraction, leave both blocks inline.

- [ ] **Step 5.7: Commit**

```bash
git add cmd/packer/main.go
git -c user.name=oioio-space -c user.email=oioio-space@users.noreply.github.com commit -m "feat(cmd/packer): wire -format=linux-elf for Phase 1e-B

cmd/packer pack now accepts -format=linux-elf (in addition to
-format=blob legacy and -format=windows-exe Phase 1e-A). The
linux-elf branch routes to packer.PackBinary with FormatLinuxELF,
writes the resulting ELF static-PIE to -out, and prints the AEAD
key (hex) to stdout.

Help text + usage() updated to enumerate all three format options.

Smoke-tested: cmd/packer pack -format=linux-elf produces a
debug/elf-parsable ET_DYN x86_64 PIE binary.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"

git push origin master
```

**Ready to ship as commit when:**
- `go run ./cmd/packer pack --help` shows the new format option
- `cmd/packer pack -format=linux-elf` produces a parsable ELF
- /simplify findings applied

---

## Task 6: Docs + handoff bump + v0.60.0 SEMVER tag

**Files:**
- Modify: `pe/packer/runtime/doc.go`
- Modify: `docs/refactor-2026-doc/packer-design.md`
- Modify: `docs/refactor-2026-doc/HANDOFF-2026-05-06.md`

- [ ] **Step 6.1: Bump runtime/doc.go**

In `pe/packer/runtime/doc.go`, find the existing Phase 1e-A paragraph (added by the v0.59.0 task). Extend it to mention 1e-B:

```go
// Phase 1e-A and 1e-B compose on top of the runtime: pe/packer.PackBinary
// produces a runnable host binary (Windows PE32+ via FormatWindowsExe,
// or Linux ELF static-PIE via FormatLinuxELF) that, at execution,
// peels a polymorphic SGN-encoded stage-1 decoder loop and JMPs into
// an embedded stage-2 (a pre-built Go EXE that consumes this runtime
// via runtime.LoadPE). The runtime needs no changes for either
// phase — it's the unchanged second stage of the new packed-binary
// flow on both platforms.
```

- [ ] **Step 6.2: Bump packer-design.md**

In `docs/refactor-2026-doc/packer-design.md`, find the row for `1e`. Replace with:

```markdown
| 1e | Polymorphic stub generation + multi-format output. **Stage 1e-A** ✅ Windows EXE polymorphic stage-1 (v0.59.0). **Stage 1e-B** ✅ this commit: Linux ELF static-PIE host (mirror of 1e-A). Phase 1e-C (Windows DLL), 1e-D (BOF), 1e-E (.NET) staged separately. | 🟡 Stages A+B |
```

- [ ] **Step 6.3: Bump HANDOFF-2026-05-06.md**

Insert a new section near the top of the "What landed today" / "Phase 1e-A shipped" area:

```markdown
## Phase 1e-B shipped — Linux ELF host ✅

Mirror of Phase 1e-A for Linux ELF static-PIE outputs. ~600 LOC
across 5 commits (Tasks 1-5 of the
`2026-05-07-phase-1e-b-implementation.md` plan).

Reuse map (zero changes):
- `pe/packer/stubgen/amd64/` — encoder backend
- `pe/packer/stubgen/poly/` — SGN engine (substitutions, RegPool, junk, N-round)
- `pe/packer/stubgen/stage1/` — Round.Emit per-decoder-loop emitter

New surface:
- `pe/packer/stubgen/host/elf.go` — `EmitELF` mirror of `EmitPE`. ET_DYN
  static-PIE, no PT_DYNAMIC, no PT_INTERP — passes Phase 1f Stage E gate.
- `pe/packer/stubgen/stubvariants/stage2_linux_v01` — Linux Go static-PIE
  built from the existing cross-platform `stage2_main.go`.
- `stubgen.HostFormat` enum + `Generate` / `PickStage2Variant` dispatch.
- `packer.FormatLinuxELF` + `PackBinary` Linux case.
- `cmd/packer pack -format=linux-elf` CLI wire.

At runtime: ELF entry → stage 1 SGN decoder loops (raw amd64,
OS-agnostic; SP intact for kernel-set frame) → JMP into stage 2's
`_rt0_amd64_linux` → Go runtime initializes from kernel-set
argc/argv on SP → main reads sentinel-located trailer →
`runtime.LoadPE` from Phase 1f Stage C+D → JMP to original payload OEP.

Validated: all unit tests green; whole-module + cross-OS
(Windows/Darwin) builds clean. E2E execution test (run the
generated ELF and capture payload stdout) deferred to the next
session — same reasoning as 1e-A's deferred Windows-VM E2E.

Recommended next moves (post-1e-B):
1. **Phase 1e-C** — Windows DLL host (DLL sideload scenarios).
2. **Phase 1e-D** — BOF (Beacon Object File) for Cobalt Strike.
3. **Phase 1e-E** — .NET assembly host.
4. **Stage-2 v02..v08** — additional committed variants per format.
5. **Linux ELF E2E test** running the packed binary on the host.
```

In the Track 3 status table, update the 1e row:

```markdown
| **1e** | **Stages A+B: polymorphic stub gen + Windows EXE + Linux ELF outputs** (1e-C/D/E reserved) | ✅ v0.60.0 |
```

Bump the front-matter `reflects_commit` at commit time (will be replaced after push).

- [ ] **Step 6.4: Whole-module sanity**

```bash
go build $(go list ./... | grep -v scripts/x64dbg-harness)
go test -count=1 ./pe/packer/... ./cmd/packer/
GOOS=windows go build $(go list ./... | grep -v scripts/x64dbg-harness)
GOOS=darwin go build $(go list ./... | grep -v scripts/x64dbg-harness)
```

Expected: clean.

- [ ] **Step 6.5: /simplify on the docs diff**

Apply findings inline.

- [ ] **Step 6.6: Commit + push + tag**

```bash
git add pe/packer/runtime/doc.go docs/refactor-2026-doc/packer-design.md docs/refactor-2026-doc/HANDOFF-2026-05-06.md
git -c user.name=oioio-space -c user.email=oioio-space@users.noreply.github.com commit -m "docs(packer): Phase 1e-B shipped — Linux ELF host + handoff bump

Mark Phase 1e row in packer-design.md as Stages A+B ✅. Bump
runtime/doc.go to mention the cross-platform end-to-end flow
(runtime is the unchanged stage 2 on both Windows and Linux).
Add 'Phase 1e-B shipped' section in HANDOFF-2026-05-06.md
documenting the new ELF host emitter, the committed Linux
stage-2 variant, the CLI wiring, and the next-moves order
(1e-C Windows DLL, 1e-D BOF, 1e-E .NET, stage-2 v02..v08, Linux
ELF E2E).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"

git push origin master

git -c user.name=oioio-space -c user.email=oioio-space@users.noreply.github.com tag -a v0.60.0 -m "Phase 1e-B — Linux ELF host (mirror of 1e-A for ELF static-PIE)"
git push origin v0.60.0
```

**Ready to ship as commit when:**
- All 5 previous tasks committed and pushed
- Whole-module build clean
- /simplify pass complete
- v0.60.0 tag pushed to origin

---

## Self-Review Checklist (run after writing this plan)

**1. Spec coverage:**

- [x] `host.EmitELF` + `ELFConfig` + `ErrEmptyStage1ELF` + `ErrEmptyPayloadELF` → Task 1
- [x] `host/doc.go` mentions both formats → Task 1
- [x] `stage2_linux_v01` committed binary + Makefile target + README → Task 2
- [x] `stubgen.HostFormat` enum + `ErrUnsupportedHostFormat` → Task 3
- [x] `stubgen.PickStage2Variant` format-aware → Task 3
- [x] `stubgen.Generate` HostFormat dispatch → Task 3
- [x] Embedded `stage2V01ELF` byte slice → Task 3
- [x] `pe/packer.FormatLinuxELF` constant + `Format.String()` update → Task 4
- [x] `pe/packer.PackBinary` Linux dispatch → Task 4
- [x] `cmd/packer pack -format=linux-elf` → Task 5
- [x] `pe/packer/runtime/doc.go` 1e-B mention → Task 6
- [x] `packer-design.md` 1e row update → Task 6
- [x] `HANDOFF-2026-05-06.md` 1e-B section → Task 6
- [x] v0.60.0 tag → Task 6

E2E test running the generated ELF binary on Linux is explicitly deferred to a next session — same reasoning as 1e-A's deferred Windows VM E2E.

**2. Placeholder scan:** No "TBD", "TODO", "implement later" patterns. All steps have concrete code or commands.

**3. Type consistency:**
- `host.ELFConfig` defined in Task 1, consumed by Task 3 via `host.EmitELF(host.ELFConfig{...})` — field names align.
- `stubgen.HostFormat` defined in Task 3, consumed by Task 4 via `stubgen.HostFormatPE` / `stubgen.HostFormatELF` — names match.
- `stubgen.Options.HostFormat` field added in Task 3, set in Task 4 — same field name.
- `packer.Format` enum extended in Task 4, used in Task 5 via `packer.FormatLinuxELF`.
- Sentinel byte sequence implicit (Task 3 reuses Task 8 of 1e-A's existing `sentinel` constant; no new declaration).

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-05-07-phase-1e-b-implementation.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration. Best for plans where reviews catch design drifts (we caught a critical SGN-substitution bug via this in 1e-A's Task 4).

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints. Faster end-to-end but no review gate between tasks.

Which approach?
