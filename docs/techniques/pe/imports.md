# PE Import Table Analysis

[← Back to PE index](README.md)

Parse a PE file's import directory to enumerate every DLL dependency
and the specific function names imported from each. Useful for static
triage, binary diffing, and feeding `evasion/unhook` / `wsyscall` which
only need to unhook/resolve the functions the implant actually imports.

- **Package:** `github.com/oioio-space/maldev/pe/imports`
- **MITRE ATT&CK:** T1106 — Native API (discovery of imported APIs)
- **Platform:** cross-platform (operates on PE bytes — no loader required)
- **Detection:** N/A — static analysis only.

## How it works

1. The package reads the PE optional header, locates the `IMAGE_DIRECTORY_ENTRY_IMPORT`
   table and walks each `IMAGE_IMPORT_DESCRIPTOR`.
2. For each descriptor it follows `OriginalFirstThunk` (or `FirstThunk` if
   the original is zero) to resolve each imported function name, handling
   both by-name and by-ordinal entries.
3. Cross-platform: works on a Windows host reading its own PEs, and on
   Linux/macOS reading a Windows PE byte stream (no `DbgHelp` / `LoadLibrary`
   dependency).

## Example

```go
package main

import (
    "fmt"

    "github.com/oioio-space/maldev/pe/imports"
)

func main() {
    imps, err := imports.List(`C:\Windows\System32\notepad.exe`)
    if err != nil {
        panic(err)
    }
    for _, imp := range imps {
        fmt.Printf("%s!%s\n", imp.DLL, imp.Function)
    }
}
```

Typical output (truncated):

```text
KERNEL32.dll!GetProcAddress
KERNEL32.dll!LoadLibraryW
USER32.dll!GetMessageW
...
```

## Pairing with unhook / wsyscall

```go
// Only unhook functions the implant actually calls.
imps, _ := imports.List(selfPEPath)
targets := make([]string, 0, len(imps))
for _, i := range imps {
    if i.DLL == "ntdll.dll" {
        targets = append(targets, i.Function)
    }
}
errs := evasion.ApplyAll(unhook.ClassicAll(targets), caller)
```

This reduces the unhook noise (fewer bytes rewritten, fewer EDR crumbs)
vs. `unhook.Full()` which rewrites the entire `.text` section of `ntdll`.

## Detection considerations

- Reading your own process image (`os.Args[0]`) is normal — any loader
  walks its own imports during startup.
- Reading a disk PE (e.g., `notepad.exe`) via normal I/O is a
  filesystem read, not an EDR trigger.

## Related

- [PE Sanitization](strip-sanitize.md) — strip metadata *before* analysing.
- [`evasion/unhook`](../evasion/ntdll-unhooking.md) — natural consumer
  of the import list for targeted unhooking.
