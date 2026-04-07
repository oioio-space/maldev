[← Back to README](../README.md)

# PE Operations

This page documents the six PE-related packages in maldev:

- **`pe/parse`** -- Parse, inspect, and write PE files (cross-platform)
- **`pe/morph`** -- Mutate UPX section headers to break automatic unpackers
- **`pe/srdi`** -- Convert a DLL into position-independent shellcode (sRDI)
- **`pe/cert`** -- Read, write, copy, and strip Authenticode certificates
- **`pe/strip`** -- Sanitize Go PE binaries (timestamps, pclntab, section names)
- **`pe/bof`** -- Beacon Object File (BOF) loader for in-memory COFF execution

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

---

## pe/cert -- Authenticode Certificate Manipulation

Package `cert` provides read, write, copy, and strip operations for PE Authenticode certificates. Useful for signature cloning (copying a valid certificate from a signed binary to an unsigned payload) and certificate stripping.

**MITRE ATT&CK:** T1553.002 (Subvert Trust Controls: Code Signing)
**Platform:** Cross-platform (operates on raw PE bytes)
**Detection:** Low -- certificate manipulation leaves no runtime artifacts; modified PE files may fail signature verification.

### Types

#### `Certificate`

```go
type Certificate struct {
    Raw []byte // WIN_CERTIFICATE structure(s) including headers
}
```

Holds the raw Authenticode certificate data extracted from a PE file.

### Errors

```go
var (
    ErrNoCertificate = errors.New("PE file has no Authenticode certificate")
    ErrInvalidPE     = errors.New("invalid PE file")
)
```

### Functions

#### `Read`

```go
func Read(pePath string) (*Certificate, error)
```

**Purpose:** Extracts the Authenticode certificate from a PE file.

**Parameters:**
- `pePath` -- Path to the PE file on disk.

**Returns:** A `*Certificate` containing the raw WIN_CERTIFICATE data, or `ErrNoCertificate` if the file has no certificate.

**How it works:** Reads the PE file, locates the security directory entry (data directory index 4), and copies the certificate blob from the file offset.

---

#### `Has`

```go
func Has(pePath string) (bool, error)
```

**Purpose:** Checks whether a PE file contains an Authenticode certificate without extracting it.

---

#### `Strip`

```go
func Strip(pePath, dst string) error
```

**Purpose:** Removes the Authenticode certificate from a PE file.

**Parameters:**
- `pePath` -- Source PE file path.
- `dst` -- Destination path. If empty, the file is modified in place.

**How it works:** Truncates the file at the certificate offset and zeroes the security directory entry.

---

#### `Copy`

```go
func Copy(srcPE, dstPE string) error
```

**Purpose:** Copies the Authenticode certificate from one PE file to another (signature cloning). The destination file must already exist.

**Example:**

```go
import "github.com/oioio-space/maldev/pe/cert"

// Clone Microsoft's signature onto our payload
err := cert.Copy(`C:\Windows\System32\kernel32.dll`, `C:\Temp\implant.exe`)
```

---

#### `Write`

```go
func Write(pePath string, c *Certificate) error
```

**Purpose:** Writes raw certificate data to a PE file, replacing any existing certificate. The certificate blob is appended at the end of the file and the security directory entry is patched.

---

#### `Export`

```go
func (c *Certificate) Export(path string) error
```

**Purpose:** Saves the raw certificate data to a standalone file for later reuse.

---

#### `Import`

```go
func Import(path string) (*Certificate, error)
```

**Purpose:** Loads raw certificate data from a file previously saved with `Export`.

---

## pe/strip -- Go PE Binary Sanitization

Package `strip` provides PE binary sanitization to remove Go-specific metadata and compilation artifacts that fingerprint the toolchain. Breaks tools like `redress`, `GoReSym`, and IDA's `go_parser` plugin.

**MITRE ATT&CK:** T1027.002 (Obfuscated Files or Information: Software Packing)
**Platform:** Cross-platform (operates on PE byte slices)
**Detection:** Low

### Functions

#### `SetTimestamp`

```go
func SetTimestamp(peData []byte, t time.Time) []byte
```

**Purpose:** Overwrites `IMAGE_FILE_HEADER.TimeDateStamp` with the Unix epoch representation of `t`.

**Parameters:**
- `peData` -- Raw PE bytes.
- `t` -- Desired compilation timestamp.

**Returns:** The modified PE bytes (same underlying slice).

---

#### `WipePclntab`

```go
func WipePclntab(peData []byte) []byte
```

**Purpose:** Searches for the Go pclntab magic (`0xFFFFFFF1` for Go 1.20+, `0xFFFFFFF0` for Go 1.16+) and zeros the first 32 bytes of each occurrence. This breaks Go-specific analysis tools.

---

#### `RenameSections`

```go
func RenameSections(peData []byte, renames map[string]string) []byte
```

**Purpose:** Renames PE sections according to the provided map. Section names are 8-byte null-padded ASCII fields.

**Parameters:**
- `peData` -- Raw PE bytes.
- `renames` -- Map of old section name to new name, e.g., `map[string]string{".gopclntab": ".rdata2"}`.

---

#### `Sanitize`

```go
func Sanitize(peData []byte) []byte
```

**Purpose:** Applies all available sanitizations with sensible defaults: timestamp set to a random date in 2023-2024, pclntab wiped, and Go-specific sections renamed (`.gopclntab` -> `.rdata2`, `.go.buildinfo` -> `.rsrc2`, `.noptrdata` -> `.data2`).

**Example:**

```go
import (
    "os"
    "github.com/oioio-space/maldev/pe/strip"
)

raw, _ := os.ReadFile("implant.exe")
clean := strip.Sanitize(raw)
os.WriteFile("implant_clean.exe", clean, 0o644)
```

---

## pe/bof -- Beacon Object File Loader

Package `bof` provides a minimal Beacon Object File (BOF) loader for in-memory COFF execution. BOFs are compiled COFF (.o) object files that can be loaded and executed without writing a full PE to disk.

**MITRE ATT&CK:** T1059 (Command and Scripting Interpreter)
**Platform:** Windows (amd64)
**Detection:** Medium -- executable memory allocation (RWX) is visible to EDR, but the payload never touches disk.

### Types

#### `BOF`

```go
type BOF struct {
    Data  []byte
    Entry string // entry point function name (default: "go")
}
```

Represents a parsed COFF object file. Set `Entry` before calling `Execute` to specify a custom entry point function name.

### Functions

#### `Load`

```go
func Load(data []byte) (*BOF, error)
```

**Purpose:** Parses a COFF object file from raw bytes. Validates the COFF header and machine type (x64 only).

**Parameters:**
- `data` -- Raw COFF object file bytes (.o file).

**Returns:** A `*BOF` ready for execution, or an error if the file is invalid or not x64.

---

#### `Execute`

```go
func (b *BOF) Execute(args []byte) ([]byte, error)
```

**Purpose:** Runs the BOF's entry point with the given arguments. The BOF is loaded into executable memory, relocations are applied, and the entry function is called using the BOF calling convention: `go(char *data, int len)`.

**Parameters:**
- `args` -- Raw argument bytes passed to the BOF entry function. Pass `nil` for no arguments.

**Returns:** Output bytes (currently `nil`) and any execution error.

**How it works:**
1. Parses section headers from the COFF data.
2. Locates the `.text` section containing machine code.
3. Allocates RWX memory via `VirtualAlloc` and copies the `.text` data.
4. Applies COFF relocations (`IMAGE_REL_AMD64_ADDR64`, `IMAGE_REL_AMD64_ADDR32NB`, `IMAGE_REL_AMD64_REL32`).
5. Resolves the entry point symbol from the COFF symbol table.
6. Calls the entry function via `syscall.Syscall`.
7. Frees the executable memory on return.

**Limitations:**
- Beacon API functions (`BeaconOutput`, `BeaconFormatAlloc`, etc.) are NOT resolved. BOFs that call Beacon APIs will crash.
- Only x64 COFF files are supported.
- Only basic relocation types are handled.

**Example:**

```go
import (
    "log"
    "os"

    "github.com/oioio-space/maldev/pe/bof"
)

func main() {
    data, err := os.ReadFile("mybof.o")
    if err != nil {
        log.Fatal(err)
    }

    b, err := bof.Load(data)
    if err != nil {
        log.Fatal(err)
    }

    _, err = b.Execute(nil)
    if err != nil {
        log.Fatal(err)
    }
}
```
