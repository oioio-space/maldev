---
last_reviewed: 2026-05-09
reflects_commit: eab7429
---

# Worked example — Packer Elevation Tour (v0.66 → v0.70)

[← examples index](README.md) · [docs/index](../index.md)

## What this is

A guided side-by-side tour of every packer mode the maldev project
ships, from the original v0.61 PE/ELF in-place transform to the
v0.69 318-byte all-asm bundle. Run the snippets against a single
toy payload (`exit 42` shellcode) and watch the resulting binary
sizes and on-disk artefacts evolve.

Aimed at someone learning what these techniques actually *cost* and
what they actually *give*.

## The fixture: a 12-byte shellcode

Every variant below packs the same minimal Linux x86-64 shellcode:

```
xor edi, edi    ; clear arg
mov dil, 42     ; arg = 42
mov eax, 60     ; sys_exit
syscall
```

12 bytes, calls `_exit(42)`. Succeeding runs are visible by checking
`$?`.

## Variant 1 — `transform.BuildMinimalELF64` (raw)

Just wrap the shellcode in a kernel-loadable ELF, no packer logic.

```go
out, _ := transform.BuildMinimalELF64(exit42Shellcode)
os.WriteFile("v1-raw", out, 0o755)
// 132 bytes — the canonical Brian-Raiter "tiny ELF" shape.
```

| Attribute | Value |
|---|---|
| Total size | **132 B** |
| Stub asm | 0 (none) |
| Encryption | none |
| .text RWX | yes (single PT_LOAD) |
| Process tree | 1 binary |
| /proc/self/maps | one anonymous-ish PT_LOAD |
| Pedagogy | Brian Raiter (2002): the smallest legal ELF |

## Variant 2 — `WrapBundleAsExecutableLinux` (all-asm)

```go
bundle, _ := packer.PackBinaryBundle(
    []packer.BundlePayload{{
        Binary: exit42Shellcode,
        Fingerprint: packer.FingerprintPredicate{
            PredicateType: packer.PTMatchAll,
        },
    }},
    packer.BundleOptions{},
)
out, _ := packer.WrapBundleAsExecutableLinux(bundle)
os.WriteFile("v2-allasm", out, 0o755)
// 318 bytes (varies a few bytes with key randomization).
```

| Attribute | Value |
|---|---|
| Total size | **~318 B** |
| Stub asm | 73 B hand-rolled (call/pop PIC + XOR-decrypt + JMP) |
| Encryption | XOR rolling 16-byte key |
| .text RWX | yes (single PT_LOAD) |
| Process tree | 1 binary |
| /proc/self/maps | one PT_LOAD |
| Pedagogy | minimum viable polymorphic loader |

The 318 bytes break down as:

```
  120 B  ELF header + lone PT_LOAD Phdr
   73 B  stub asm
   32 B  BundleHeader
   48 B  FingerprintEntry  (PTMatchAll)
   32 B  PayloadEntry      (DataRVA + DataSize + 16 B key)
   12 B  encrypted shellcode
  ─────
  ~318 B
```

That's ~24× smaller than the 7.6 KiB minimum for a bare `gcc -static -no-pie`
hello-world. The trade-off: payload must be position-independent
shellcode (the stub jumps directly into it; PE/ELF headers would crash).

## Variant 3 — `cmd/bundle-launcher` + `AppendBundle` (Go runtime)

```bash
$ go build -o bundle-launcher ./cmd/bundle-launcher
$ packer bundle -wrap bundle-launcher -bundle v2-allasm-bundle-blob.bin -out v3-go
```

| Attribute | Value |
|---|---|
| Total size | **~5 MB** (Go runtime baseline) |
| Stub | Go runtime — not asm |
| Encryption | XOR rolling 16-byte key |
| Predicate eval | full (CPUID + Win build + Negate) |
| Fallback modes | Exit / First / Crash |
| Process tree | 2 binaries (launcher → execve payload) |
| /proc/self/maps | shows `/tmp/.../bundle-payload-*` for the matched payload |
| Pedagogy | the operator-friendly path: full feature set, slow/loud |

## Variant 4 — `cmd/bundle-launcher` reflective (`MALDEV_REFLECTIVE=1`)

```bash
$ MALDEV_REFLECTIVE=1 ./v3-go
```

Same 5 MB binary, different dispatch mode. The matched payload gets
mapped into the launcher's address space via `pe/packer/runtime.Prepare`
and entered on a fake kernel stack. No fork, no execve, no temp file.

| Attribute | Value |
|---|---|
| Total size | **~5 MB** |
| Stub | Go runtime + asm trampoline |
| Predicate eval | full (CPUID + Win build + Negate) |
| Process tree | **1 binary** (no execve) |
| /proc/self/maps | anonymous regions for the payload |
| Pedagogy | reflective loading done right — auxv patching, segment mapping, RELATIVE relocs |

## Side-by-side at a glance

| Variant | Size | Stub | Predicate | Proc tree | Disk artefact |
|---------|-----:|------|-----------|-----------|---------------|
| 1 — raw min-ELF | 132 B | none | none | 1 | none |
| **2 — all-asm bundle** | **318 B** | 73 B asm | idx 0 only (today) | 1 | none |
| 3 — Go launcher (default) | ~5 MB | Go | full | 2 | temp file |
| 4 — Go launcher reflective | ~5 MB | Go + asm | full | **1** | none |

Trade-off curve: variant 2 wins binary size and OPSEC at the cost of
predicate evaluation; variant 4 wins everything except size; variant 3
is the most operator-friendly default.

## Visualising

`cmd/packer-vis` (v0.70.0) renders both the entropy of any of these
binaries and the bundle wire format:

```bash
$ packer-vis entropy v1-raw     # 132-byte file, all near-min entropy bins
$ packer-vis entropy v2-allasm  # the encrypted 12-byte payload region
                                # shows up as a high-entropy ▆▇█ smear

$ packer-vis bundle bundle-blob.bin
  bundle.bin
  256 bytes | magic=0x56444c4d version=0x1 count=2 fallback=0

  ┌─ BundleHeader ─────────────────────────────────────┐
  │ 0x00..0x20  magic + version + count + offsets     │
  │            fpTable=0x20    plTable=0x80    data=0xc0 │
  └────────────────────────────────────────────────────┘

  ┌─ [0] FingerprintEntry @ 0x20 ────────────────────┐
  │ predType=0x01  vendor="GenuineIntel"  build=[22000, 99999] │
  └────────────────────────────────────────────────────┘
  ...
```

## Limitations recap

- Variant 2 (all-asm) selects payload 0 unconditionally today. The
  full CPUID+PEB evaluator is queued (`EmitVendorCompare` and
  `EmitBuildRangeCheck` primitives are already in tree) — drops in
  without changing `WrapBundleAsExecutableLinux`'s public signature.
- Variant 2's payload must be raw position-independent shellcode.
  PE/ELF payloads need variant 3 or 4.
- Windows symmetry of the all-asm path (a `MinimalPE32Plus` writer
  + Windows fingerprint dispatch) is queued for a future minor.

## See also

- [`pe/packer.WrapBundleAsExecutableLinux`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/packer#WrapBundleAsExecutableLinux)
- [`pe/packer/transform.BuildMinimalELF64`](https://pkg.go.dev/github.com/oioio-space/maldev/pe/packer/transform#BuildMinimalELF64)
- [`cmd/bundle-launcher`](https://pkg.go.dev/github.com/oioio-space/maldev/cmd/bundle-launcher)
- [`cmd/packer-vis`](https://pkg.go.dev/github.com/oioio-space/maldev/cmd/packer-vis)
- [Plan: packer elevation roadmap](../superpowers/plans/2026-05-09-packer-elevation.md)
