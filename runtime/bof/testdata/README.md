# runtime/bof example BOFs

> Source for example BOFs that exercise the loader's Beacon API
> stubs + dollar-import resolver. The compiled `.o` files are not
> committed because they require mingw-w64 cross-compilation
> from this Linux dev box; the build is reproducible from the
> sources here.

## Build

```bash
# One-time toolchain install on a Fedora/Debian dev box.
dnf install mingw64-gcc      # Fedora
apt install mingw-w64        # Debian/Ubuntu

# Build all examples.
cd runtime/bof/testdata
for src in *.c; do
    x86_64-w64-mingw32-gcc -c "$src" -o "${src%.c}.o" \
        -O2 -Wall -ffreestanding -fno-stack-protector
done
```

The flags mirror the Cobalt-Strike convention: `-c` (compile only,
emit COFF), `-O2 -Wall` (sensible defaults), `-ffreestanding`
(no libc startup), `-fno-stack-protector` (CS BOFs do not link
`__chkstk`).

## Examples

### `hello_beacon.c` — BeaconPrintf round-trip

Smallest possible BOF that proves the Beacon API surface works:

- Imports `__imp_BeaconPrintf` (resolved by the Beacon API stub
  table to the Go callback that appends to the BOF's output
  buffer).
- Entry point `go(char *, int)` prints a fixed greeting plus
  the args buffer's first byte.
- After load, `BOF.Execute` should return the printed string.

### `parse_args.c` — Beacon data-parser round-trip

Exercises the data-parsing API:

- Imports `__imp_BeaconDataParse`, `__imp_BeaconDataInt`,
  `__imp_BeaconDataExtract`, `__imp_BeaconPrintf`.
- Reads (int32, length-prefixed string) from the args buffer,
  prints them via BeaconPrintf.
- Caller pre-packs the args via `bof.NewArgs().AddInt(...).AddString(...).Pack()`.

### `loadlib.c` — dollar-import resolution

Proves the `__imp_<DLL>$<Func>` resolver path works for a
real Win32 import:

- Imports `__imp_KERNEL32$LoadLibraryA` and
  `__imp_KERNEL32$GetModuleHandleA`.
- Entry point loads a benign DLL ("crypt32.dll"), retrieves
  its handle, prints the handle as hex via BeaconPrintf,
  then unloads.
- Confirms the PEB walk + ROR13 export-table match patches in
  the real kernel32 entry-point address (no GetProcAddress /
  LoadLibrary import in the BOF's COFF symbol table beyond
  the dollar-import name itself).

## Test wiring

Each `.o` is committed to `testutil/` next to the existing
`nop.o` / `whoami.o` once built locally. Test files in
`runtime/bof/` (e.g. `realbof_windows_test.go`) load them via
`testutil.LoadPayload(t, "<name>.o")`.

## Status

- [ ] `hello_beacon.c` source written, .o build pending
- [ ] `parse_args.c` source written, .o build pending
- [ ] `loadlib.c` source written, .o build pending
- [ ] Tests authored once .o files land

This file unblocks future contributors: once mingw is available,
running the build commands above produces the missing artefacts
without further design work.
