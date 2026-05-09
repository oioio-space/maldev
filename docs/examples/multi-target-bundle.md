---
last_reviewed: 2026-05-09
reflects_commit: 6f03f26
---

# Worked example — multi-target bundle (C6)

[← examples index](README.md) · [docs/index](../index.md)

## Goal

Ship one binary that carries N independent payloads, each
matched against a target environment by CPUID vendor + Windows
build number. At run time, only the payload matching the host
gets decrypted; the others remain as opaque XOR-encrypted blobs
in memory and on disk.

This is the v0.67.0-alpha.1 ship of [`pe/packer.PackBinaryBundle`][pkg]
(spec §3 wire format) plus the host-side selection oracle
[`pe/packer.SelectPayload`][sel] and the operator CLI's new
`packer bundle` subcommand. The runtime stub-side fingerprint
evaluator (asm CPUID/PEB read + decryption) is queued for C6-P3
and C6-P4; until it ships, the bundle is a build-host artefact
you can author, inspect, and sanity-check today.

[pkg]: https://pkg.go.dev/github.com/oioio-space/maldev/pe/packer#PackBinaryBundle
[sel]: https://pkg.go.dev/github.com/oioio-space/maldev/pe/packer#SelectPayload

## Threat model recap

What the bundle achieves now (P1-P2 shipped):

- A defender who captures the on-disk binary sees N
  encrypted blobs separated by a small plaintext header +
  fingerprint table. The fingerprint table reveals only
  *environmental constraints* ("payload 0 wants Intel + build
  ≥ 22000") — never plaintext, OEP, or imports.
- The blast radius of one extracted payload is limited: each
  payload has its own random 16-byte XOR key, so a signature
  derived from one variant does NOT match the others.

What you still need C6-P3+P4 for:

- The runtime stub that walks the table and picks the right
  payload. Until that lands, you ship the bundle blob alone
  (no PE/ELF wrapper) and the target needs an external loader.

## Step 1 — Build per-target payloads

Compile one binary per target environment. The bundle is
container-agnostic; raw bytes go in.

```bash
# Three flavours of the same payload, each tuned for one target.
GOOS=linux  GOARCH=amd64 go build -o /tmp/payload-w11.bin  ./cmd/agent  # Intel + Win11
GOOS=linux  GOARCH=amd64 go build -o /tmp/payload-w10.bin  ./cmd/agent  # AMD + Win10
GOOS=linux  GOARCH=amd64 go build -o /tmp/payload-fallback ./cmd/agent  # catch-all
```

## Step 2 — Pack the bundle (CLI)

```bash
packer bundle \
  -out      /tmp/bundle.bin \
  -pl       /tmp/payload-w11.bin:intel:22000-99999 \
  -pl       /tmp/payload-w10.bin:amd:10000-19999 \
  -pl       /tmp/payload-fallback:*:*-* \
  -fallback exit
```

Spec syntax: `<file>:<vendor>:<min>-<max>` where `vendor` ∈
`{intel | amd | *}` and `min/max` is the inclusive Windows
build-number range (`*` on either side = "no bound"). The
`-fallback` flag controls what the runtime stub does when no
predicate matches — `exit` (silent, default), `crash`
(deliberate fault), or `first` (always pick payload 0).

## Step 3 — Verify the layout

```bash
$ packer bundle -inspect /tmp/bundle.bin
bundle /tmp/bundle.bin — 1234567 bytes
  magic=0x56444c4d version=0x1 count=3 fb=0
  fpTable=0x20 plTable=0xb0 data=0x110
  [0] pred=0x03 vendor=GenuineIntel build=[22000, 99999] data=0x110..+412160
  [1] pred=0x03 vendor=AuthenticAMD build=[10000, 19999] data=0x64710..+411904
  [2] pred=0x08 vendor=*            build=[0, 0]         data=0xc7da0..+411520
```

Magic `0x56444c4d` = `"MLDV"` (little-endian). `pred=0x03` =
`PT_CPUID_VENDOR | PT_WIN_BUILD` (both checks AND-combined);
`pred=0x08` = `PT_MATCH_ALL` (catch-all).

## Step 4 — Build-host preview (Go API)

Operators can preview which payload would fire on a given
target without running the binary, using `SelectPayload`:

```go
package main

import (
    "fmt"
    "log"
    "os"

    "github.com/oioio-space/maldev/pe/packer"
)

func main() {
    bundle, err := os.ReadFile("/tmp/bundle.bin")
    if err != nil { log.Fatal(err) }

    // Simulate target 1: Intel + Windows 11 23H2.
    intel := [12]byte{'G','e','n','u','i','n','e','I','n','t','e','l'}
    if idx, _ := packer.SelectPayload(bundle, intel, 22631); idx >= 0 {
        fmt.Printf("Intel/W11 → payload %d\n", idx)
    }

    // Simulate target 2: AMD + Windows 10 21H2.
    amd := [12]byte{'A','u','t','h','e','n','t','i','c','A','M','D'}
    if idx, _ := packer.SelectPayload(bundle, amd, 19041); idx >= 0 {
        fmt.Printf("AMD/W10 → payload %d\n", idx)
    }

    // Simulate target 3: unknown vendor (sandbox?). Falls to PTMatchAll.
    unknown := [12]byte{'B','o','c','h','s','C','P','U','i','d','x','5'}
    if idx, _ := packer.SelectPayload(bundle, unknown, 9600); idx >= 0 {
        fmt.Printf("unknown → payload %d (catch-all)\n", idx)
    }
}
```

Output:

```
Intel/W11 → payload 0
AMD/W10 → payload 1
unknown → payload 2 (catch-all)
```

If you remove the catch-all entry and re-pack, the unknown
target returns `idx == -1` — the runtime stub will fall back to
the configured `-fallback` behaviour (clean exit, by default).

## Step 5 — Decrypt one payload (build-host debugging)

`UnpackBundle` is the inverse of the encryption pass. Use it on
the build host to extract a specific payload for analysis or
sanity-check:

```go
plaintext, err := packer.UnpackBundle(bundle, 0)  // payload 0 (Intel/W11)
if err != nil { log.Fatal(err) }
os.WriteFile("/tmp/recovered-w11.bin", plaintext, 0o644)
```

The recovered bytes are byte-identical to the original
`payload-w11.bin` you fed into `PackBinaryBundle`.

> NOT a runtime helper. The on-disk per-payload XOR key is
> trivially reversible once an attacker has the bundle blob.
> The runtime stub (C6-P3) re-derives the same key in asm
> after the fingerprint match — no plaintext key crosses the
> Go heap unless the predicate matched.

## Programmatic equivalent (no CLI)

```go
intel := [12]byte{'G','e','n','u','i','n','e','I','n','t','e','l'}
amd   := [12]byte{'A','u','t','h','e','n','t','i','c','A','M','D'}

bundle, err := packer.PackBinaryBundle([]packer.BundlePayload{
    {Binary: payloadW11, Fingerprint: packer.FingerprintPredicate{
        PredicateType: packer.PTCPUIDVendor | packer.PTWinBuild,
        VendorString:  intel,
        BuildMin:      22000, BuildMax: 99999,
    }},
    {Binary: payloadW10, Fingerprint: packer.FingerprintPredicate{
        PredicateType: packer.PTCPUIDVendor | packer.PTWinBuild,
        VendorString:  amd,
        BuildMin:      10000, BuildMax: 19999,
    }},
    {Binary: payloadFallback, Fingerprint: packer.FingerprintPredicate{
        PredicateType: packer.PTMatchAll,
    }},
}, packer.BundleOptions{FallbackBehaviour: packer.BundleFallbackExit})
```

## Limitations (current shipping state)

- **No runtime stub yet.** The bundle is a flat blob; you can
  inspect / decrypt it on the build host but not yet `exec` it
  directly. C6-P3 (asm fingerprint evaluator) and C6-P4 (PE/ELF
  wrapping with bundle entry-point) close this gap.
- **XOR-rolling cipher only.** Per spec §9 Q8, the v1 wire format
  uses XOR with a 16-byte rolling key. A stronger design would
  derive the key from the fingerprint result so it never lives
  on disk; deferred to C6-phase-2.
- **Plaintext fingerprint table.** The predicates themselves
  reveal which environments are targets. Operators who want to
  hide that signal can pad with decoy entries that point to
  random-noise payloads.
- **CPUID vendor + Windows build only.** Spec §4 leaves room for
  more predicate types (CPUID feature mask, RDTSC timing, …);
  none are wired through `SelectPayload` yet beyond what the
  wire format allows.

## See also

- Spec: [`docs/superpowers/specs/2026-05-08-packer-multi-target-bundle.md`](../superpowers/specs/2026-05-08-packer-multi-target-bundle.md)
- Tech md: [`docs/techniques/pe/packer.md`](../techniques/pe/packer.md)
- UPX-style single-payload variant: [`docs/examples/upx-style-packer.md`](upx-style-packer.md)
