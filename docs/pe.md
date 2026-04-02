[← Back to README](../README.md)

# PE Operations

This page documents the three PE-related packages in maldev:

- **`pe/parse`** -- Parse, inspect, and write PE files (cross-platform)
- **`pe/morph`** -- Mutate UPX section headers to break automatic unpackers
- **`pe/srdi`** -- Convert a DLL into position-independent shellcode (sRDI)

---

## pe/parse -- PE File Parsing

Package `parse` wraps Go's `debug/pe` with additional helpers for maldev operations: section enumeration, export resolution, import listing, and raw byte access for modification.

**Platform:** Cross-platform (parses Windows PE files on any OS).

### Types

#### `File`

```go
type File struct {
    PE   *pe.File  // Standard library PE handle
    Raw  []byte    // Raw file bytes (mutable for patching)
    Path string    // Original file path or name
}
```

The central type. All methods operate on this struct. `Raw` is the mutable byte buffer -- modify it directly for binary patching, then call `Write` or `WriteBytes` to persist.

---

### Functions

#### `Open`

```go
func Open(path string) (*File, error)
```

**Purpose:** Open a PE file from disk, read it into memory, and parse its headers.

**Parameters:**
- `path` -- Filesystem path to the PE file (EXE, DLL, SYS, etc.)

**Returns:** A parsed `*File` or an error if the file cannot be read or is not a valid PE.

**How it works:** Reads the entire file into `Raw` via `os.ReadFile`, then delegates to `FromBytes` for parsing.

**Example:**

```go
package main

import (
    "fmt"
    "log"

    "github.com/oioio-space/maldev/pe/parse"
)

func main() {
    f, err := parse.Open(`C:\Windows\System32\kernel32.dll`)
    if err != nil {
        log.Fatal(err)
    }
    defer f.Close()

    fmt.Printf("64-bit: %v\n", f.Is64Bit())
    fmt.Printf("DLL:    %v\n", f.IsDLL())
    fmt.Printf("Base:   0x%X\n", f.ImageBase())
    fmt.Printf("Entry:  0x%X\n", f.EntryPoint())
}
```

---

#### `FromBytes`

```go
func FromBytes(data []byte, name string) (*File, error)
```

**Purpose:** Parse a PE from raw bytes already in memory. Useful when the PE was downloaded, decrypted, or generated in memory without touching disk.

**Parameters:**
- `data` -- Raw PE bytes (must start with `MZ` header)
- `name` -- Descriptive name stored in `File.Path` (used for logging/debugging)

**Returns:** A parsed `*File` or a parse error.

**How it works:** Creates a `bytes.Reader` over the data and calls `pe.NewFile` from the standard library.

**Example:**

```go
package main

import (
    "fmt"
    "log"
    "os"

    "github.com/oioio-space/maldev/pe/parse"
)

func main() {
    data, err := os.ReadFile(`C:\payload.dll`)
    if err != nil {
        log.Fatal(err)
    }

    f, err := parse.FromBytes(data, "payload.dll")
    if err != nil {
        log.Fatal(err)
    }
    defer f.Close()

    fmt.Printf("Sections: %d\n", len(f.Sections()))
}
```

---

#### `Close`

```go
func (f *File) Close() error
```

**Purpose:** Release resources held by the underlying `debug/pe.File`. Always defer this after `Open` or `FromBytes`.

---

#### `Is64Bit`

```go
func (f *File) Is64Bit() bool
```

**Purpose:** Returns `true` if the PE uses an `OptionalHeader64` (IMAGE_FILE_MACHINE_AMD64). Returns `false` for 32-bit PE files.

**How it works:** Type-asserts the optional header to `*pe.OptionalHeader64`.

---

#### `IsDLL`

```go
func (f *File) IsDLL() bool
```

**Purpose:** Returns `true` if the `IMAGE_FILE_DLL` characteristic flag is set in the COFF header. Use this to distinguish DLLs from EXEs.

---

#### `ImageBase`

```go
func (f *File) ImageBase() uint64
```

**Purpose:** Returns the preferred virtual address where the PE loader maps the image. For 64-bit images this is typically `0x180000000` (DLLs) or `0x140000000` (EXEs). For 32-bit images the value is zero-extended to `uint64`.

**When to use:** Calculating RVA-to-VA conversions for manual relocation or export resolution.

---

#### `EntryPoint`

```go
func (f *File) EntryPoint() uint32
```

**Purpose:** Returns the Relative Virtual Address (RVA) of the entry point. For DLLs this is `DllMain`; for EXEs it is the CRT startup routine.

---

#### `Sections`

```go
func (f *File) Sections() []*pe.Section
```

**Purpose:** Returns all section headers (`.text`, `.rdata`, `.data`, `.rsrc`, etc.). Each section exposes `Name`, `VirtualSize`, `VirtualAddress`, `Size`, and `Offset`.

---

#### `SectionByName`

```go
func (f *File) SectionByName(name string) *pe.Section
```

**Purpose:** Find a specific section by exact name (e.g., `.text`, `.rsrc`, `UPX0`). Returns `nil` if the section does not exist.

**Parameters:**
- `name` -- Exact section name (case-sensitive, max 8 chars in PE)

**Example:**

```go
package main

import (
    "fmt"
    "log"

    "github.com/oioio-space/maldev/pe/parse"
)

func main() {
    f, err := parse.Open(`C:\Windows\System32\ntdll.dll`)
    if err != nil {
        log.Fatal(err)
    }
    defer f.Close()

    text := f.SectionByName(".text")
    if text != nil {
        fmt.Printf(".text VirtualAddress: 0x%X, VirtualSize: 0x%X\n",
            text.VirtualAddress, text.VirtualSize)
    }
}
```

---

#### `SectionData`

```go
func (f *File) SectionData(sec *pe.Section) ([]byte, error)
```

**Purpose:** Returns the raw bytes of a section. Use this to extract code from `.text`, resources from `.rsrc`, or data from any section.

**Parameters:**
- `sec` -- A section pointer obtained from `Sections()` or `SectionByName()`

---

#### `Exports`

```go
func (f *File) Exports() ([]string, error)
```

**Purpose:** Returns the names of all exported functions from a DLL. Returns `nil, nil` (no error) for PEs without an export directory.

**How it works:** Manually parses the export directory from raw bytes. Reads the `IMAGE_EXPORT_DIRECTORY` at data directory index 0, walks the `AddressOfNames` array, and resolves each null-terminated ASCII name from the RVA.

**Example:**

```go
package main

import (
    "fmt"
    "log"

    "github.com/oioio-space/maldev/pe/parse"
)

func main() {
    f, err := parse.Open(`C:\Windows\System32\kernel32.dll`)
    if err != nil {
        log.Fatal(err)
    }
    defer f.Close()

    exports, err := f.Exports()
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("kernel32.dll exports %d functions\n", len(exports))
    for _, name := range exports[:5] {
        fmt.Println(" ", name)
    }
}
```

---

#### `Imports`

```go
func (f *File) Imports() ([]string, error)
```

**Purpose:** Returns the names of imported DLLs (e.g., `KERNEL32.dll`, `ntdll.dll`). Delegates to `debug/pe.File.ImportedLibraries()`.

**When to use:** Reconnaissance -- discover what DLLs a target binary depends on before injection or hooking.

---

#### `Write`

```go
func (f *File) Write(path string) error
```

**Purpose:** Saves the `Raw` bytes to disk. Call this after modifying `Raw` to persist binary patches.

**Parameters:**
- `path` -- Destination file path (created with 0644 permissions)

---

#### `WriteBytes`

```go
func (f *File) WriteBytes() []byte
```

**Purpose:** Returns the raw PE bytes. Use this when you need the modified PE in memory (e.g., to feed it to `pe/srdi` or encrypt it for staging).

---

## pe/morph -- UPX Header Mutation

Package `morph` replaces UPX section names with random strings to defeat automatic unpackers and change the file hash. MITRE ATT&CK: T1027.002 (Software Packing).

### Functions

#### `UPXMorph`

```go
func UPXMorph(peData []byte) ([]byte, error)
```

**Purpose:** Replaces all section names containing "UPX" with random 8-byte strings. This prevents tools like `upx -d` from recognizing and automatically decompressing the binary, and changes the file hash for signature evasion.

**Parameters:**
- `peData` -- Raw bytes of a UPX-packed PE file

**Returns:** The modified PE bytes. If the file is not UPX-packed (no sections contain "UPX"), the data is returned unchanged.

**How it works:**
1. Parses the PE to enumerate section headers
2. For each section whose name contains "UPX", calculates the file offset of the section header's Name field using the COFF header layout
3. Overwrites the 8-byte Name field with cryptographically random bytes via `random.RandomString`

**Example:**

```go
package main

import (
    "log"
    "os"

    "github.com/oioio-space/maldev/pe/morph"
)

func main() {
    // Read a UPX-packed binary
    data, err := os.ReadFile("packed.exe")
    if err != nil {
        log.Fatal(err)
    }

    // Randomize UPX section names
    morphed, err := morph.UPXMorph(data)
    if err != nil {
        log.Fatal(err)
    }

    // Write the morphed binary
    if err := os.WriteFile("morphed.exe", morphed, 0755); err != nil {
        log.Fatal(err)
    }
}
```

---

#### `UPXFix`

```go
func UPXFix(peData []byte) ([]byte, error)
```

**Purpose:** Restores original UPX section names (`UPX0`, `UPX1`, `UPX2`) after a `UPXMorph` operation. This allows the binary to be decompressed with `upx -d` again.

**Parameters:**
- `peData` -- Raw bytes of a previously morphed UPX-packed PE

**Returns:** The restored PE bytes. Returns an error if the PE has fewer than 3 sections (standard UPX packing produces exactly 3).

**How it works:** Writes the fixed names `UPX0`, `UPX1`, `UPX2` (null-padded to 8 bytes) into the first three section header Name fields.

**When to use:** During development or testing when you need to unpack a morphed binary for analysis.

**Example:**

```go
package main

import (
    "log"
    "os"

    "github.com/oioio-space/maldev/pe/morph"
)

func main() {
    data, err := os.ReadFile("morphed.exe")
    if err != nil {
        log.Fatal(err)
    }

    fixed, err := morph.UPXFix(data)
    if err != nil {
        log.Fatal(err)
    }

    if err := os.WriteFile("fixed.exe", fixed, 0755); err != nil {
        log.Fatal(err)
    }
    // Now: upx -d fixed.exe will work
}
```

---

## pe/srdi -- DLL-to-Shellcode Conversion

Package `srdi` converts a PE DLL into position-independent shellcode using Shellcode Reflective DLL Injection (sRDI). The generated shellcode loads the DLL entirely from memory without touching disk.

**MITRE ATT&CK:** T1055.001 (Process Injection: DLL Injection)
**Platform:** Cross-platform (generates Windows x64 shellcode on any OS)
**Detection:** Medium -- the generated shellcode performs in-memory DLL loading.

### Types

#### `Config`

```go
type Config struct {
    FunctionName     string // Exported function to call after loading (optional)
    Parameter        string // String parameter passed to the function (optional)
    ClearHeader      bool   // Remove PE header from memory after loading (evasion)
    ObfuscateImports bool   // Obfuscate import table resolution (evasion)
}
```

Controls shellcode generation behavior. `ClearHeader` and `ObfuscateImports` are evasion features that make memory forensics harder.

### Functions

#### `DefaultConfig`

```go
func DefaultConfig() *Config
```

**Purpose:** Returns a sensible default configuration with `ClearHeader: true` and `ObfuscateImports: true`.

---

#### `ConvertDLL`

```go
func ConvertDLL(dllPath string, cfg *Config) ([]byte, error)
```

**Purpose:** Reads a DLL from disk and converts it into position-independent shellcode that reflectively loads itself when executed.

**Parameters:**
- `dllPath` -- Path to the DLL file on disk
- `cfg` -- Shellcode generation options (pass `nil` for defaults)

**Returns:** Raw shellcode bytes ready for injection.

**How it works:**
1. Reads the DLL from disk
2. Delegates to `ConvertDLLBytes` for the actual conversion

**Example:**

```go
package main

import (
    "fmt"
    "log"

    "github.com/oioio-space/maldev/pe/srdi"
)

func main() {
    cfg := srdi.DefaultConfig()
    cfg.FunctionName = "MyExportedFunc"
    cfg.Parameter = "hello"

    shellcode, err := srdi.ConvertDLL(`C:\payload.dll`, cfg)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Generated %d bytes of shellcode\n", len(shellcode))
    // shellcode is now ready for injection via inject.Remote() etc.
}
```

---

#### `ConvertDLLBytes`

```go
func ConvertDLLBytes(dllBytes []byte, cfg *Config) ([]byte, error)
```

**Purpose:** Converts raw DLL bytes (already in memory) into shellcode. Use this when the DLL was downloaded, decrypted, or generated without touching disk.

**Parameters:**
- `dllBytes` -- Raw DLL bytes (must start with `MZ` header)
- `cfg` -- Shellcode generation options (pass `nil` for defaults)

**Returns:** Raw shellcode bytes or an error if the input is not a valid PE.

**How it works:** The generated bootstrap shellcode performs the following steps at runtime:
1. Resolves `kernel32.dll` base address via PEB (`GS:[0x60]` on x64)
2. Walks `InMemoryOrderModuleList` to find kernel32
3. Parses the export directory for `GetProcAddress`
4. Resolves `VirtualAlloc`, `LoadLibraryA` via `GetProcAddress`
5. Allocates memory and copies PE headers + sections
6. Processes base relocations
7. Resolves imports
8. Calls TLS callbacks
9. Calls `DllMain(DLL_PROCESS_ATTACH)` or the specified `FunctionName`

**Example:**

```go
package main

import (
    "fmt"
    "log"
    "os"

    "github.com/oioio-space/maldev/pe/srdi"
)

func main() {
    dllBytes, err := os.ReadFile(`C:\payload.dll`)
    if err != nil {
        log.Fatal(err)
    }

    shellcode, err := srdi.ConvertDLLBytes(dllBytes, &srdi.Config{
        ClearHeader:      true,
        ObfuscateImports: true,
    })
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Generated %d bytes of shellcode from %d byte DLL\n",
        len(shellcode), len(dllBytes))
}
```

---

## Workflow: Parse, Morph, Convert

A common workflow combines all three packages:

```go
package main

import (
    "fmt"
    "log"
    "os"

    "github.com/oioio-space/maldev/pe/morph"
    "github.com/oioio-space/maldev/pe/parse"
    "github.com/oioio-space/maldev/pe/srdi"
)

func main() {
    // 1. Parse the DLL to inspect it
    f, err := parse.Open(`C:\payload.dll`)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("DLL: %v, 64-bit: %v, Exports:\n", f.IsDLL(), f.Is64Bit())

    exports, _ := f.Exports()
    for _, e := range exports {
        fmt.Printf("  %s\n", e)
    }
    f.Close()

    // 2. If it's UPX-packed, morph the headers
    data, _ := os.ReadFile(`C:\payload.dll`)
    morphed, err := morph.UPXMorph(data)
    if err != nil {
        log.Fatal(err)
    }

    // 3. Convert to shellcode for injection
    shellcode, err := srdi.ConvertDLLBytes(morphed, srdi.DefaultConfig())
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Shellcode: %d bytes\n", len(shellcode))
}
```
