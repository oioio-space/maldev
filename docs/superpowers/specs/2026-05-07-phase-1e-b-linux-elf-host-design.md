---
last_reviewed: 2026-05-07
reflects_commit: 7ac90de
status: draft
---

# Phase 1e-B — Linux ELF host (mirror of 1e-A for ELF static-PIE)

> Design spec locking the Linux ELF output format for the maldev
> packer. Phase 1e-A shipped the Windows EXE host + polymorphic
> SGN-style stage-1 decoder pipeline. Phase 1e-B adds the
> equivalent Linux ELF static-PIE host, reusing the entire
> stubgen/{amd64, poly, stage1} pipeline unchanged.
>
> Brainstorming session 2026-05-07 — design space narrow because
> 90% of the work is already done in 1e-A. Decisions locked per
> standing directive ("le meilleur sans paresse, philosophie du
> projet").

## Summary

| Item | Choice |
|---|---|
| Host emitter | Single package `stubgen/host` with `pe.go` + `elf.go` split. Mirrors the repo's `runtime_linux.go` + `runtime_windows.go` pattern. |
| Stage 2 Linux variant | Reuse `stage2_main.go` source (already cross-platform); rebuild via Makefile with `GOOS=linux GOARCH=amd64`. |
| Stage 1 asm | Identical to 1e-A — SGN decoder loop is OS-agnostic (raw amd64 bytes, no syscalls, no CALL/PUSH). |
| Sentinel | Same 16-byte sequence as 1e-A: `4D 41 4C 44 45 56 01 01 50 59 31 45 30 30 41 00`. Single source of truth in `stubgen/stubgen.go`. |
| ELF host shape | Static-PIE: `ET_DYN + no DT_NEEDED + no PT_INTERP`. Matches Phase 1f Stage E acceptance gate. |
| Build flags for stage 2 | `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildmode=pie -ldflags='-s -w'`. NOT `-d` (Phase 1f review confirmed `-d` breaks `.data.rel.ro` pointers). |
| Format constant | `FormatLinuxELF = 2` added to `pe/packer.Format`. |

## Decisions locked (compressed)

The Phase 1e-A pattern resolves all but six choices; those six are
answered per project philosophy:

1. **Host emitter shape**: single-package split (Option 2) over two-package isolation. Mirrors `pe/packer/runtime`'s pattern.
2. **Stage 2 source reuse**: same `stage2_main.go` (Option 3). DRY — the existing source is already cross-platform.
3. **Sentinel**: shared single constant. Per-format sentinels are over-engineering for marginal collision-risk gain.
4. **ELF host shape**: ET_DYN static-PIE. Matches Stage E gate; Phase 1f runtime already validated.
5. **Build flags**: `-buildmode=pie -ldflags='-s -w'`. Stage E review eliminated `-d` as broken for production binaries.
6. **Single-stage decomposition**: 1e-B is one ship, not multiple stages. The work is small enough (~600 LOC) and dependent on 1e-A's pipeline.

## Architecture

### Acceptance contract

`PackBinary(payload []byte, opts PackBinaryOptions{Format: FormatLinuxELF, ...})` accepts:

- `payload` — arbitrary bytes (typically a Linux static-PIE the
  operator wants to deploy). Phase 1c+ pipeline encrypts upstream;
  PackBinary takes raw payload + handles end-to-end packaging.
- `opts.Format = FormatLinuxELF` (new in 1e-B).
- `opts.Stage1Rounds`, `opts.Pipeline`, `opts.Seed` — unchanged
  semantics from 1e-A.

### Output contract

Returns `(host []byte, key []byte, err error)`:

- `host` — a complete Linux ELF64 LE x86_64 static-PIE executable.
  When `chmod +x`-ed and run, self-decrypts via stage 1, JMPs into
  stage 2, which loads the original payload via `pe/packer/runtime`.
- `key` — AEAD key for the user's payload (same shape as 1e-A).

### Two-stage runtime flow

```
ELF entry (host)
   │
   ▼
[stage 1: SGN-encoded amd64 decoder loop, fresh bytes per pack]
   • round N peels XOR layer N
   • round N-1 peels layer N-1
   • …
   • round 1 peels layer 1 → stage2 || encryptedPayload
   • JMP into stage 2's entry (RIP-relative)
   ▼
[stage 2: pre-built Linux Go static-PIE]
   • _rt0_amd64_linux reads SP for argc/argv (kernel-set frame survives stage 1)
   • Go runtime initializes (arch_prctl SET_FS for TLS — Stage E pattern)
   • main.main: os.Executable → /proc/self/exe → bytes.Index sentinel
   • read u64 payloadLen + u64 keyLen + payload + key trailer
   • runtime.LoadPE(payload, key) → fake stack frame + JMP to OEP (Phase 1f Stage C+D)
   ▼
[original payload runs]
```

### File layout

```
pe/packer/stubgen/
├── host/
│   ├── doc.go                          # MODIFY: mention both formats
│   ├── pe.go                           # existing
│   ├── pe_test.go                      # existing
│   ├── elf.go                          # NEW — EmitELF + ErrInvalid* sentinels for ELF
│   └── elf_test.go                     # NEW — debug/elf parse-back + reject-empty-input
├── stubvariants/
│   ├── stage2_main.go                  # existing (already cross-platform)
│   ├── Makefile                        # MODIFY: add `stage2_linux_v01` target
│   ├── stage2_v01.exe                  # existing
│   ├── stage2_linux_v01                # NEW — committed Linux ELF binary (~5 MB)
│   └── README.md                       # MODIFY: document Linux variant + sentinel format
├── stubgen.go                          # MODIFY:
│                                       #   - PickStage2Variant takes format param
│                                       #   - Options gains HostFormat field
│                                       #   - Generate dispatches host.EmitPE vs EmitELF
└── stubgen_test.go                     # MODIFY: add ELF Generate test

pe/packer/packer.go                     # MODIFY:
                                        #   - add FormatLinuxELF const
                                        #   - PackBinary FormatLinuxELF case

cmd/packer/main.go                      # MODIFY:
                                        #   - -format flag accepts "linux-elf"
```

### `host.EmitELF` signature

```go
type ELFConfig struct {
    Stage1Bytes []byte // emitted asm — goes into the PT_LOAD code segment
    PayloadBlob []byte // encoded stage 2 || encrypted payload — goes into the PT_LOAD data segment
}

// EmitELF writes a complete Linux ELF64 LE x86_64 static-PIE
// executable wrapping stage 1 (in code segment) + payload blob
// (in data segment). Output passes the Phase 1f Stage E gate
// (ET_DYN + no DT_NEEDED + no PT_INTERP) so the runtime can
// reflectively load it.
//
// Sentinels: ErrEmptyStage1ELF, ErrEmptyPayloadELF.
func EmitELF(cfg ELFConfig) ([]byte, error)
```

### Stage 2 Linux build

Make target in `Makefile`:

```makefile
stage2_linux_v01: stage2_main.go
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		$(GO) build -trimpath \
		-buildmode=pie \
		-ldflags='-s -w -buildid=' \
		-o $@ ./$<
```

The committed binary is a Go static-PIE that:
1. `os.Executable()` returns the path of the running binary
2. `os.ReadFile(path)` reads its own bytes
3. `bytes.Index(self, sentinel)` locates the trailer
4. Reads u64 payloadLen + u64 keyLen
5. Extracts payload + key
6. Calls `pkgrt.LoadPE(payload, key)` then `img.Run()`

The exact same `stage2_main.go` source as 1e-A — runtime.LoadPE
on Linux dispatches to `mapAndRelocateELF` (Phase 1f Stage E),
which handles Go and non-Go static-PIE inputs.

## Components

### `pe/packer/stubgen/host/elf.go` (NEW)

```go
package host

import (
    "encoding/binary"
    "errors"
    "fmt"
)

var (
    ErrEmptyStage1ELF  = errors.New("host: Stage1Bytes is empty (ELF)")
    ErrEmptyPayloadELF = errors.New("host: PayloadBlob is empty (ELF)")
)

// ELF64 layout constants (System V ABI Rev 1.0).
const (
    elfMagic0      = 0x7F
    elfClass64     = 2
    elfDataLE      = 1
    elfVersion     = 1
    elfOSABISysv   = 0
    eTypeDyn       = 3
    eMachineX86_64 = 62

    ehdrSize  = 64
    phdrSize  = 56
    pageSize  = 0x1000
    elfPF_X   = 1
    elfPF_W   = 2
    elfPF_R   = 4
    ptLoad    = 1
)

// EmitELF emits a 2-PT_LOAD static-PIE ELF64. PT_LOAD #1 (R+E)
// holds stage 1 asm; PT_LOAD #2 (R) holds the encoded payload
// blob. ET_DYN + no PT_DYNAMIC + no PT_INTERP — matches Phase 1f
// Stage E runtime gate.
func EmitELF(cfg ELFConfig) ([]byte, error) {
    if len(cfg.Stage1Bytes) == 0 {
        return nil, ErrEmptyStage1ELF
    }
    if len(cfg.PayloadBlob) == 0 {
        return nil, ErrEmptyPayloadELF
    }

    // Compute layout: header → phdr table → text segment (stage1) →
    // data segment (payload). Each PT_LOAD page-aligned.
    phdrCount := uint16(2)
    phdrTableSize := uint32(phdrCount) * phdrSize

    textOffset := alignUp(ehdrSize+phdrTableSize, pageSize)
    textSize := alignUp(uint32(len(cfg.Stage1Bytes)), pageSize)
    textVAddr := uint64(textOffset)

    dataOffset := textOffset + textSize
    dataSize := alignUp(uint32(len(cfg.PayloadBlob)), pageSize)
    dataVAddr := uint64(dataOffset)

    totalSize := dataOffset + dataSize
    out := make([]byte, totalSize)

    // ELF identification
    out[0] = elfMagic0
    out[1] = 'E'
    out[2] = 'L'
    out[3] = 'F'
    out[4] = elfClass64
    out[5] = elfDataLE
    out[6] = elfVersion
    out[7] = elfOSABISysv
    // 8..15 = padding (zero)

    // Ehdr fields
    binary.LittleEndian.PutUint16(out[16:18], eTypeDyn)
    binary.LittleEndian.PutUint16(out[18:20], eMachineX86_64)
    binary.LittleEndian.PutUint32(out[20:24], elfVersion)
    binary.LittleEndian.PutUint64(out[24:32], textVAddr) // e_entry = stage 1 start
    binary.LittleEndian.PutUint64(out[32:40], ehdrSize)  // e_phoff
    // e_shoff = 0 (no section headers — minimal ELF)
    binary.LittleEndian.PutUint32(out[48:52], 0)         // e_flags
    binary.LittleEndian.PutUint16(out[52:54], ehdrSize)
    binary.LittleEndian.PutUint16(out[54:56], phdrSize)
    binary.LittleEndian.PutUint16(out[56:58], phdrCount)
    // e_shentsize / e_shnum / e_shstrndx = 0

    // PT_LOAD #1: text (R+E)
    writeProgHdr(out[ehdrSize:ehdrSize+phdrSize],
        ptLoad, elfPF_R|elfPF_X,
        uint64(textOffset), textVAddr, textVAddr,
        uint64(len(cfg.Stage1Bytes)), uint64(len(cfg.Stage1Bytes)),
        pageSize)

    // PT_LOAD #2: data (R)
    writeProgHdr(out[ehdrSize+phdrSize:ehdrSize+2*phdrSize],
        ptLoad, elfPF_R,
        uint64(dataOffset), dataVAddr, dataVAddr,
        uint64(len(cfg.PayloadBlob)), uint64(len(cfg.PayloadBlob)),
        pageSize)

    // Section bodies
    copy(out[textOffset:], cfg.Stage1Bytes)
    copy(out[dataOffset:], cfg.PayloadBlob)

    return out, nil
}

// writeProgHdr emits one Elf64_Phdr (56 bytes) to dst.
func writeProgHdr(dst []byte, pType uint32, pFlags uint32,
    pOffset, pVAddr, pPAddr, pFileSz, pMemSz, pAlign uint64) {
    binary.LittleEndian.PutUint32(dst[0:4], pType)
    binary.LittleEndian.PutUint32(dst[4:8], pFlags)
    binary.LittleEndian.PutUint64(dst[8:16], pOffset)
    binary.LittleEndian.PutUint64(dst[16:24], pVAddr)
    binary.LittleEndian.PutUint64(dst[24:32], pPAddr)
    binary.LittleEndian.PutUint64(dst[32:40], pFileSz)
    binary.LittleEndian.PutUint64(dst[40:48], pMemSz)
    binary.LittleEndian.PutUint64(dst[48:56], pAlign)
}

func alignUp(v, align uint32) uint32 {
    return (v + align - 1) &^ (align - 1)
}
```

### `pe/packer/stubgen/stubgen.go` extensions

```go
type HostFormat uint8

const (
    HostFormatPE  HostFormat = 0
    HostFormatELF HostFormat = 1
)

// Options gains HostFormat (default PE for backwards compat — 1e-A
// callers don't change). Generate dispatches:
type Options struct {
    Inner       []byte
    Rounds      int
    Seed        int64
    HostFormat  HostFormat // NEW
}

// PickStage2Variant takes a format param.
func PickStage2Variant(seed int64, format HostFormat) ([]byte, error) {
    switch format {
    case HostFormatPE:
        return stage2V01PE, nil
    case HostFormatELF:
        return stage2V01ELF, nil
    default:
        return nil, ErrUnsupportedHostFormat
    }
}

// Generate dispatches to host.EmitPE or host.EmitELF based on HostFormat.
func Generate(opts Options) ([]byte, error) {
    // ... encode + stage1 emit unchanged ...
    switch opts.HostFormat {
    case HostFormatPE:
        return host.EmitPE(host.PEConfig{Stage1Bytes: stage1Bytes, PayloadBlob: encoded})
    case HostFormatELF:
        return host.EmitELF(host.ELFConfig{Stage1Bytes: stage1Bytes, PayloadBlob: encoded})
    default:
        return nil, ErrUnsupportedHostFormat
    }
}

// New embed for Linux variant
//go:embed stubvariants/stage2_linux_v01
var stage2V01ELF []byte
```

### `pe/packer/packer.go` extensions

```go
const (
    FormatUnknown    Format = iota
    FormatWindowsExe        // existing
    FormatLinuxELF          // NEW
)

func (f Format) String() string {
    switch f {
    case FormatWindowsExe: return "windows-exe"
    case FormatLinuxELF:   return "linux-elf"
    default:               return fmt.Sprintf("format(%d)", uint8(f))
    }
}

func PackBinary(payload []byte, opts PackBinaryOptions) (host []byte, key []byte, err error) {
    // ... validate Format ...
    var hostFormat stubgen.HostFormat
    switch opts.Format {
    case FormatWindowsExe:
        hostFormat = stubgen.HostFormatPE
    case FormatLinuxELF:
        hostFormat = stubgen.HostFormatELF
    default:
        return nil, nil, fmt.Errorf("%w: %s", ErrUnsupportedFormat, opts.Format)
    }
    // ... rest unchanged, threads hostFormat through PickStage2Variant + Generate ...
}
```

## Data flow

Identical to 1e-A except:
- `PickStage2Variant(seed, FormatELF)` returns `stage2V01ELF` instead of `stage2V01PE`
- `host.EmitELF` instead of `host.EmitPE`
- Output is ELF64 not PE32+

## Error handling

New sentinels (`host/elf.go`):
- `ErrEmptyStage1ELF` — empty stage 1 input
- `ErrEmptyPayloadELF` — empty payload blob

New sentinel (`stubgen/stubgen.go`):
- `ErrUnsupportedHostFormat` — fires when Generate / PickStage2Variant gets an unknown HostFormat

Existing sentinels (`ErrInvalidRounds`, `ErrPayloadTooLarge`,
`ErrEncodingSelfTestFailed`, `ErrNoStage2Variant`,
`ErrStage2SentinelMissing`, `ErrUnsupportedFormat`) propagate unchanged.

## Testing strategy

### Unit tests

1. **`host.TestEmitELF_ParsesViaDebugELF`** — emit, parse via
   `debug/elf.NewFile`, assert ELFCLASS64, EM_X86_64, ET_DYN, exactly
   2 PT_LOAD program headers.

2. **`host.TestEmitELF_RejectsEmptyStage1`** — nil Stage1Bytes →
   ErrEmptyStage1ELF.

3. **`host.TestEmitELF_RejectsEmptyPayload`** — nil PayloadBlob →
   ErrEmptyPayloadELF.

4. **`stubgen.TestPickStage2Variant_ELF`** — PickStage2Variant(seed,
   HostFormatELF) returns the embedded Linux Go binary, parses
   cleanly via `debug/elf.NewFile`.

5. **`stubgen.TestGenerate_LinuxELF_ProducesParsableELF`** — full
   Generate call with HostFormatELF; result parses via debug/elf
   with 2 PT_LOAD segments + the entry point pointing into the
   first PT_LOAD's range.

6. **`packer.TestPackBinary_LinuxELF_ProducesParsableELF`** — full
   PackBinary(payload, FormatLinuxELF); result is a static-PIE
   ELF that passes Phase 1f's `runtime.CheckELFLoadable`.

### Cross-platform sanity

- All `pe/packer/stubgen/host/elf.go` and tests are pure-Go and
  cross-platform (debug/elf is read-only stdlib, no syscalls).
- `GOOS=windows go build ./...` and `GOOS=darwin go build ./...`
  must stay clean.

### E2E (deferred, out of scope for 1e-B)

Running the generated ELF on a Linux box and asserting payload
output. Same pattern as Phase 1f Stage C+D's `TestRun_GoStaticPIE_E2E`
but for a packed binary. Requires `MALDEV_PACKER_RUN_E2E=1` + a
real test payload (e.g., the existing
`pe/packer/runtime/testdata/hello_static_pie`).

The E2E test belongs to the next session — same reasoning as 1e-A
deferred its Windows-VM E2E test.

## Future work (out of scope)

- **Phase 1e-C** — Windows DLL host (DLL sideload scenarios).
- **Phase 1e-D** — BOF (Beacon Object File) for Cobalt Strike.
- **Phase 1e-E** — .NET assembly host.
- **Stage-2 v02..v08** — additional variants (per-format) for
  byte uniqueness.
- **Linux ELF E2E test** running the packed binary.

## See also

- `docs/superpowers/specs/2026-05-07-phase-1e-a-polymorphic-packer-stub-design.md` — Phase 1e-A design (this spec mirrors).
- `pe/packer/runtime/runtime_linux.go` — Phase 1f Stage C+D mapper used by stage 2.
- `pe/packer/runtime/elf.go` — `CheckELFLoadable` gate; the generated ELF must pass it.
- `docs/refactor-2026-doc/packer-design.md` — phase plan; row 1e gets ✅ Stages A+B on ship.
- `docs/refactor-2026-doc/HANDOFF-2026-05-06.md` — running cross-machine state.
