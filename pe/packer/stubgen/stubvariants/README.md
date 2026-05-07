# Phase 1e-A/B stage-2 stub variants

This directory holds the pre-built Go binaries that the packer wraps
as the second-stage loader.  Each variant is a compiled `stage2_main.go`
that, at runtime:

1. Locates its embedded payload via a 16-byte sentinel sequence
   (appended by the packer at pack-time).
2. Reads `payloadLen` and `keyLen` from the 16 bytes immediately
   after the sentinel (two little-endian `uint64` values).
3. Extracts the payload bytes and AEAD key from the trailer that
   follows the length fields.
4. Calls `pe/packer/runtime.LoadPE` to reflectively load and run
   the original payload (JMP to OEP).

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

Maintainer-only operation.  Operators consuming `packer.PackBinary`
use the committed binaries directly — they do not rebuild them.

```bash
cd pe/packer/stubgen/stubvariants/
make all  # builds both stage2_v01.exe + stage2_linux_v01
```

Requires `go` on `PATH`.  Build flags pin `-trimpath -s -w
-buildid=''` for byte-stability across CI rebuilds.  Linux variant
adds `-buildmode=pie`.

## Sentinel format

```
[16 bytes sentinel] [u64 payloadLen LE] [u64 keyLen LE] [payload bytes] [key bytes]
```

Sentinel value (hex):

```
4D 41 4C 44 45 56 01 01  50 59 31 45 30 30 41 00
```

Human-readable: `MALDEV\x01\x01PY1E00A\x00`

Offsets are little-endian.  Total trailer size = 32 + payloadLen +
keyLen bytes appended to the stage-2 binary at pack-time.
`PackBinary` (`stubgen.go`) must declare the identical sentinel
constant to locate the patch point.

## Audit

Each committed binary should match `make stage2_vNN.exe` or
`make stage2_linux_vNN` from the same Go toolchain version.  The
`-buildid=''` flag removes the per-build nonce so successive rebuilds
of identical source produce identical bytes modulo toolchain version.
A drift check belongs to a future CI workflow; for now maintainers
verify by hand.
