# maldev Roadmap v2 — Design Spec

**Date:** 2026-04-14
**Author:** Claude + Mathieu
**Approach:** Hybrid sprints thematiques (Approche C)
**Timeline:** 12 semaines (6 sprints de 2 semaines)

## Constraints

- **NO CGO** anywhere in the project. Use purego, x/sys/windows, or raw syscalls.
- All new packages must support `*wsyscall.Caller` where NT syscalls are involved.
- All NT-level calls must support the **SSN resolvers** from `win/syscall` (Hell's Gate, Halo's Gate, Tartarus Gate, Hash Gate, Chain).
- Every exported function must have tests, doc.go with MITRE ATT&CK ID, detection level.
- All external code must be credited in README Acknowledgments.
- Prefer existing maldev functions over reimplementing (pe/parse, win/token, inject/, etc.).
- Single `go.mod` at root. No workspace.

---

## Sprint 1 (Weeks 1-2): Fondations critiques

### 1.1 ADS — Alternate Data Streams CRUD

**Package:** `system/ads/`
**MITRE:** T1564.004 — Hide Artifacts: NTFS File Attributes
**Source:** go-winio `backup.go` (rewrite, not vendor)
**Credit:** microsoft/go-winio
**Refs:**
- https://github.com/microsoft/go-winio/blob/main/backup.go
- https://cqureacademy.com/blog/alternate-data-streams/

**API:**

```go
// List returns all alternate data streams on a file.
func List(path string) ([]StreamInfo, error)

// Read reads the content of a named ADS.
func Read(path, streamName string) ([]byte, error)

// Write creates or overwrites a named ADS.
func Write(path, streamName string, data []byte) error

// Delete removes a named ADS.
func Delete(path, streamName string) error

// CreateHidden creates a file with reserved name tricks ("...", "CON", etc.)
// that makes it hard to delete via Explorer/cmd.
func CreateHidden(dir, payload string) (string, error)
```

**Implementation:**
- Use `BackupRead`/`BackupWrite` Win32 APIs via `win/api` DLL handles
- Stream enumeration via `FindFirstStreamW`/`FindNextStreamW`
- ADS delete via `DeleteFile("path:streamName")`
- Hidden files: create via `NtCreateFile` with reserved names (bypass Win32 validation)
- Support optional `*wsyscall.Caller` for NT-level operations

**Integration with existing code:**
- `cleanup/selfdelete/` already uses ADS rename (`:deadbeef`). After this, selfdelete can use `ads.Write()` for cleaner code.
- `persistence/` can gain ADS-based persistence (hide payload in ADS of legitimate file).

**Tests:**
- TestListStreams, TestWriteRead, TestDelete, TestCreateHidden
- Integration: TestSelfDeleteUsesADS (verify cleanup/selfdelete still works)

---

### 1.2 go-donut — PE/DLL/EXE to Shellcode

**Package:** `pe/srdi/` (replaces existing placeholder)
**MITRE:** T1055.001 — Process Injection: DLL Injection (shellcode variant)
**Source:** Binject/go-donut (fork + modernize)
**Credit:** Binject/go-donut, TheWover/donut
**Refs:**
- https://github.com/Binject/go-donut
- https://github.com/TheWover/donut

**API (replaces existing placeholder):**

```go
// Config controls shellcode generation.
type Config struct {
    Arch       Arch   // X32, X64, X84 (dual)
    Class      string // DLL function to call (optional)
    Method     string // .NET method name (optional)
    Parameters string // command-line parameters
    Entropy    int    // 0=none, 1=random names, 2=random+encrypt
    Compress   int    // 0=none, 1=aPLib, 2=LZNT1, 3=Xpress
    Bypass     int    // 0=none, 1=abort on detection, 2=AMSI+WLDP bypass, 3=continue
}

// ConvertFile converts a PE/DLL/.NET/VBS/JS file to position-independent shellcode.
func ConvertFile(path string, cfg *Config) ([]byte, error)

// ConvertBytes converts in-memory PE/DLL bytes to shellcode.
func ConvertBytes(data []byte, cfg *Config) ([]byte, error)
```

**Implementation:**
- Fork Binject/go-donut algorithm (~600 lines + loader stubs)
- Replace deprecated `ioutil` with `os`/`io`
- Replace `Binject/debug` PE parser with stdlib `debug/pe` + our `pe/parse`
- Embed loader stubs as `//go:embed` resources
- Support: native EXE, native DLL, .NET EXE/DLL, VBScript, JScript

**Why fork instead of import:**
- go-donut last updated 2021, uses deprecated APIs
- `Binject/debug` PE parser conflicts with stdlib
- We want to use our own `pe/parse` for consistency
- Removes external dependency

**Tests:**
- TestConvertNativeEXE, TestConvertNativeDLL, TestConvertDotNetEXE
- TestConvertWithEncryption, TestConvertWithCompression
- VM test: inject converted shellcode via CreateThread, verify execution

---

### ~~1.3 Registry CRUD~~ REMOVED

> **Raison:** `golang.org/x/sys/windows/registry` couvre déjà le CRUD registry.
> Les appels registry ne passent pas par des NT syscalls routables par notre Caller/SSN resolvers,
> donc un wrapper n'apporte aucune plus-value. Les packages existants (`persistence/registry/`,
> `evasion/antivm/`) utilisent directement `x/sys/windows/registry` — c'est suffisant.

---

### 1.4 README sobre + Wiki preparation

**README:** Keep install + quick start + project structure + acknowledgments (~60 lines).
Move all technique references, API docs, and guide links to the GitHub Wiki.

**Wiki structure:**
```
Home.md
Getting-Started.md
Architecture.md
OPSEC-Build-Pipeline.md
Testing.md
MITRE-ATT&CK.md
Techniques/
  Injection/
  Evasion/
  Syscalls/
  C2/
  PE/
  Persistence/
  Collection/
  Cleanup/
  Tokens/
  Crypto/
API/
  evasion.md
  injection.md
  syscalls.md
  ...
Examples/
  Basic-Implant.md
  Evasive-Injection.md
  Full-Chain.md
```

---

## Sprint 2 (Weeks 3-4): Evasion avancee

### 2.1 FakeCmdLine — PEB CommandLine Overwrite

**Package:** `evasion/fakecmd/`
**MITRE:** T1036.005 — Masquerading: Match Legitimate Name or Location
**Source:** gtworek/PSBits FakeOwnCmdLine.c (rewrite in Go)
**Credit:** gtworek/PSBits
**Refs:**
- https://github.com/gtworek/PSBits/blob/master/FakeCmdLine/FakeOwnCmdLine.c

**API:**

```go
// Spoof overwrites the current process PEB CommandLine with a fake string.
// Process Explorer, wmic, Get-Process will show the fake command line.
func Spoof(fakeCmd string) error

// Restore restores the original command line (saved before spoofing).
func Restore() error
```

**Implementation:**
- `NtQueryInformationProcess(ProcessBasicInformation)` to get PEB address
- Read `PEB.ProcessParameters` → `CommandLine` UNICODE_STRING
- Save original, overwrite with fake via direct memory write (same process)
- Support optional `*wsyscall.Caller` for NtQueryInformationProcess

---

### 2.2 TrustedInstaller Impersonation

**Package:** `win/impersonate/` (add to existing)
**MITRE:** T1134.001 — Access Token Manipulation: Token Impersonation
**Source:** FourCoreLabs/TrustedInstallerPOC (rewrite)
**Credit:** FourCoreLabs/TrustedInstallerPOC
**Refs:**
- https://github.com/FourCoreLabs/TrustedInstallerPOC
- https://fourcore.io/blogs/no-more-access-denied-i-am-trustedinstaller

**API:**

```go
// RunAsTrustedInstaller starts the TrustedInstaller service, opens its process,
// and spawns a child process inheriting the TI token via PPID spoofing.
// Requires admin + SeDebugPrivilege.
func RunAsTrustedInstaller(cmd string, args ...string) (*exec.Cmd, error)
```

**Implementation:**
- Start TrustedInstaller service via SCM (`StartService`)
- Find TI PID via `process/enum.FindByName("TrustedInstaller.exe")`
- Open with `PROCESS_CREATE_PROCESS` (reuse `c2/shell.PPIDSpoofer` pattern)
- Spawn child with `SysProcAttr.ParentProcess` = TI handle
- Use existing `win/privilege.IsAdmin()`, `win/token.EnablePrivilege()`

---

### 2.3 HideProcess — NtQuerySystemInformation Patch

**Package:** `evasion/hideprocess/`
**MITRE:** T1564.001 — Hide Artifacts: Hidden Process
**Source:** S3cur3Th1sSh1t/Creds HideProcess_Patch.cpp (rewrite)
**Credit:** S3cur3Th1sSh1t
**Refs:**
- https://github.com/S3cur3Th1sSh1t/Creds/blob/master/cpp/HideProcess_Patch.cpp

**API:**

```go
// PatchProcessMonitor patches NtQuerySystemInformation in the target process
// (e.g., taskmgr.exe, procexp.exe) to return STATUS_NOT_IMPLEMENTED,
// making it unable to list processes.
func PatchProcessMonitor(pid int, caller *wsyscall.Caller) error
```

**Implementation:**
- OpenProcess with PROCESS_VM_WRITE | PROCESS_VM_OPERATION
- Find `NtQuerySystemInformation` address in target's ntdll
- Write `mov eax, 0xC0000002; ret` (STATUS_NOT_IMPLEMENTED)
- Uses existing `win/ntapi` for remote memory write

---

### 2.4 StealthOpen — File Access by NTFS Object ID

**Package:** `evasion/stealthopen/`
**MITRE:** T1036 — Masquerading
**Source:** gtworek/PSBits StealthOpen.c (rewrite)
**Credit:** gtworek/PSBits
**Refs:**
- https://github.com/gtworek/PSBits/blob/master/NTFSObjectID/StealthOpen.c

**API:**

```go
// OpenByID opens a file using its NTFS Object ID (GUID) instead of path.
// Bypasses path-based EDR monitoring.
func OpenByID(volumePath string, objectID [16]byte) (*os.File, error)

// GetObjectID retrieves the NTFS Object ID of a file.
func GetObjectID(path string) ([16]byte, error)

// SetObjectID assigns an NTFS Object ID to a file.
func SetObjectID(path string, objectID [16]byte) error
```

---

### 2.5 New Callback Shellcode Methods

**Package:** `inject/` (extend existing callback_windows.go)
**Source:** OsandaMalith/CallbackShellcode
**Credit:** OsandaMalith/CallbackShellcode
**Refs:**
- https://github.com/OsandaMalith/CallbackShellcode

**New callbacks:**

```go
const (
    CallbackReadDirectoryChanges      CallbackMethod = "readdirchanges"
    CallbackNtNotifyChangeDirectory   CallbackMethod = "ntnotifychange"
    CallbackRtlRegisterWait           CallbackMethod = "rtlregisterwait"
)
```

**Implementation:**
- ReadDirectoryChangesW: allocate RWX, start directory monitoring with shellcode as callback
- NtNotifyChangeDirectoryFileEx: NT API variant, routes through Caller
- RtlRegisterWait: register shellcode as wait callback on event object

---

### 2.6 CLR Hosting — In-Process .NET Assembly Execution

**Package:** `pe/clr/`
**MITRE:** T1620 — Reflective Code Loading
**Source:** ropnop/go-clr (rewrite + modernize)
**Credit:** ropnop/go-clr
**Refs:**
- https://github.com/ropnop/go-clr
- https://github.com/lesnuages/go-execute-assembly (reference only, not used — requires native DLL)

**API:**

```go
// Runtime represents a loaded CLR runtime (.NET Framework v2 or v4).
type Runtime struct { ... }

// Load initializes the CLR in the current process.
// Prefers .NET v4, falls back to v2. Caller routes COM syscalls.
func Load(caller *wsyscall.Caller) (*Runtime, error)

// InstalledRuntimes returns all .NET Framework versions available on the system.
func InstalledRuntimes() ([]string, error)

// ExecuteAssembly loads a .NET EXE from memory and executes its entry point.
// Returns captured stdout/stderr output.
func (r *Runtime) ExecuteAssembly(assembly []byte, args []string) (string, error)

// ExecuteDLL loads a .NET DLL from memory and invokes a specific method.
func (r *Runtime) ExecuteDLL(dll []byte, typeName, methodName, arg string) (int, error)
```

**Implementation:**
- COM vtable wrappers: ICLRMetaHost, ICLRRuntimeInfo, ICORRuntimeHost
- `AppDomain.Load_3()` for in-memory .NET EXE loading via SafeArray
- Replace `syscall.NewLazyDLL` with `win/api` DLL handles
- Route COM calls through optional `*wsyscall.Caller` where possible
- Capture stdout: redirect `Console.SetOut` to capture .NET console output
- Prerequisite: `evasion/amsi.PatchAll()` before loading hostile assemblies

**Complements go-donut:**
- `pe/clr/` = run .NET in current process (Seatbelt, SharpHound, Rubeus)
- `pe/srdi/` = convert .NET to shellcode for injection into remote process via `inject/`

---

### 2.7 EnableAllPrivileges

**Package:** `win/token/` (add function to existing)
**Refs:**
- https://github.com/gtworek/PSBits/blob/master/EnableAllParentPrivileges/EnableAllParentPrivileges.c

**API:**

```go
// EnableAll enables every privilege present in the token.
func EnableAll(token windows.Token) error
```

**Implementation:** `GetTokenInformation(TokenPrivileges)` → loop → `AdjustTokenPrivileges` for each.

---

## Sprint 3 (Weeks 5-6): Post-exploitation & Collection

### 3.1 Browser Data Extraction

**Package:** `collection/browser/`
**MITRE:** T1555.003 — Credentials from Password Stores: Credentials from Web Browsers
**Source:** moonD4rk/HackBrowserData (concepts + crypto)
**Credit:** moonD4rk/HackBrowserData
**Refs:**
- https://github.com/moonD4rk/HackBrowserData

**API:**

```go
type BrowserData struct {
    Passwords  []Password
    Cookies    []Cookie
    History    []HistoryEntry
    Bookmarks  []Bookmark
    Downloads  []Download
    CreditCards []CreditCard
}

// Extract extracts data from all detected browsers.
func Extract() (*BrowserData, error)

// ExtractFrom extracts data from a specific browser.
func ExtractFrom(browser Browser) (*BrowserData, error)

// Browsers returns all detected browsers on the system.
func Browsers() []Browser
```

**Supported browsers:** Chrome, Edge, Brave, Opera, Vivaldi, Firefox (Chromium SQLite + Firefox NSS).

**Implementation:**
- Chromium: decrypt via DPAPI (`CryptUnprotectData`) + AES-GCM (v10+ encrypted with app-bound key)
- Firefox: `key4.db` (NSS) + `logins.json` (3DES-CBC decryption)
- Cross-platform: Windows (DPAPI), Linux (gnome-keyring/kwallet), macOS (Keychain)
- SQLite via pure Go `modernc.org/sqlite` (no CGO)

---

### 3.2 In-Memory LSASS Minidump

**Package:** `collection/minidump/`
**MITRE:** T1003.001 — OS Credential Dumping: LSASS Memory
**Source:** S3cur3Th1sSh1t/Creds minidump.cpp (rewrite)
**Credit:** S3cur3Th1sSh1t
**Refs:**
- https://github.com/S3cur3Th1sSh1t/Creds/blob/master/cpp/minidump.cpp

**API:**

```go
// Dump creates an in-memory minidump of lsass.exe using MiniDumpWriteDump
// with a callback that captures chunks in memory instead of writing to disk.
// Returns the raw minidump bytes.
func Dump(caller *wsyscall.Caller) ([]byte, error)

// DumpPID creates an in-memory minidump of any process by PID.
func DumpPID(pid int, caller *wsyscall.Caller) ([]byte, error)
```

**Implementation:**
- Find lsass.exe PID via `process/enum.FindByName("lsass.exe")`
- Enable SeDebugPrivilege via `win/token`
- Open lsass with PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
- Call `MiniDumpWriteDump` with `MINIDUMP_CALLBACK_INFORMATION` pointing to Go callback
- Callback accumulates chunks in `[]byte` buffer — dump never touches disk
- Route OpenProcess through optional Caller

---

### 3.3 Secrets Dumper (SAM + LSA + Cached Creds + NTDS.dit)

**Package:** `collection/secrets/`
**MITRE:** T1003.002 (SAM), T1003.004 (LSA Secrets), T1003.005 (Cached Domain Creds), T1003.003 (NTDS.dit)
**Source:** C-Sto/gosecretsdump (reference for SAM/ESE parsing) + gtworek/PSBits (LSA API approach)
**Credit:** C-Sto/gosecretsdump, gtworek/PSBits
**Refs:**
- https://github.com/C-Sto/gosecretsdump
- https://github.com/gtworek/PSBits/blob/master/LSASecretDumper/LSASecretDumper.c

**API:**

```go
type SAMEntry struct {
    Username string
    RID      uint32
    NTHash   []byte
    LMHash   []byte
}

type Secret struct {
    Name  string
    Value []byte
}

type CachedCred struct {
    Domain   string
    Username string
    Hash     []byte
}

// DumpSAM extracts SAM hashes from local registry hives.
// Requires SYSTEM token.
func DumpSAM() ([]SAMEntry, error)

// DumpSAMFromFiles parses offline SAM + SYSTEM hive files.
func DumpSAMFromFiles(samPath, systemPath string) ([]SAMEntry, error)

// DumpLSASecrets enumerates and decrypts all LSA secrets.
// Requires SYSTEM token (impersonate winlogon.exe first).
func DumpLSASecrets() ([]Secret, error)

// DumpCachedCreds extracts cached domain credentials from SECURITY hive.
// Requires SYSTEM token.
func DumpCachedCreds() ([]CachedCred, error)

// DumpNTDS parses an NTDS.dit + SYSTEM hive pair (offline AD dump).
func DumpNTDS(ntdsPath, systemPath string) ([]SAMEntry, error)
```

**Implementation:**
- **SAM hashes:** Parse SAM registry hive, decrypt with SYSTEM bootkey (RC4/AES)
- **LSA secrets:** Impersonate winlogon.exe via `win/token.StealByName()`, use `LsaRetrievePrivateData()` API
- **Cached creds:** Parse SECURITY hive `Cache\NL$X` entries, decrypt with LSA key
- **NTDS.dit:** ESE (Extensible Storage Engine) database parser for AD ntds.dit files
- Reference gosecretsdump's `pkg/ditreader`, `pkg/esent`, `pkg/samreader` for parsing logic
- Modernize: proper Go modules, error wrapping, `*wsyscall.Caller` for NT operations

---

### 3.4 LolDriverScan — Vulnerable Driver Scanner

**Package:** `system/drivers/`
**MITRE:** T1068 — Exploitation for Privilege Escalation (BYOVD recon)
**Source:** FourCoreLabs/LolDriverScan (rewrite)
**Credit:** FourCoreLabs/LolDriverScan, loldrivers.io
**Refs:**
- https://github.com/FourCoreLabs/LolDriverScan
- https://www.loldrivers.io/api/drivers.json

**API:**

```go
type VulnDriver struct {
    ServiceName string
    Path        string
    Hash        string
    Category    string // vulnerable, malicious, known_abused
    Details     string
}

// Scan enumerates all loaded drivers and cross-references against the
// loldrivers.io database. Does NOT require admin privileges.
func Scan() ([]VulnDriver, error)

// ScanFile checks a single driver file against the database.
func ScanFile(path string) (*VulnDriver, error)
```

**Implementation:**
- Embed `drivers.json` via `//go:embed` (~4MB compressed)
- Enumerate driver services via `EnumServicesStatusEx(SERVICE_DRIVER)`
- Hash each driver binary (SHA256 + authentihash via `pe/parse`)
- Cross-reference against embedded database
- Document update procedure: `curl -o system/drivers/drivers.json https://www.loldrivers.io/api/drivers.json`

---

### 3.5 Hidden Files ("..." trick)

**Package:** `system/ads/` (add to ADS package)

**API:**

```go
// CreateUndeletable creates a file using reserved name tricks
// (trailing dots, reserved names) that cannot be deleted via Explorer/cmd.
// Only NtCreateFile or \\?\ prefix can access them.
func CreateUndeletable(dir string, data []byte) (string, error)

// OpenUndeletable opens a previously created undeletable file.
func OpenUndeletable(path string) (*os.File, error)
```

---

## Sprint 4 (Weeks 7-8): Transport & C2

### 4.1 Named Pipe Transport

**Package:** `c2/transport/` (add PipeTransport)
**MITRE:** T1090.001 — Proxy: Internal Proxy (pipe-based lateral movement)
**Source:** go-winio pipe implementation (rewrite with Caller)
**Credit:** microsoft/go-winio
**Refs:**
- https://github.com/microsoft/go-winio

**API:**

```go
// NewPipe creates a named pipe transport for C2 communication.
func NewPipe(pipeName string) *Pipe

// Pipe implements the Transport interface over Windows Named Pipes.
type Pipe struct { ... }
func (p *Pipe) Connect(ctx context.Context) error
func (p *Pipe) Read(b []byte) (int, error)
func (p *Pipe) Write(b []byte) (int, error)
func (p *Pipe) Close() error

// NewPipeListener creates a named pipe server for bind shells.
func NewPipeListener(pipeName string, sd *SecurityDescriptor) (*PipeListener, error)
```

---

### 4.2 DNS-over-HTTPS Transport

**Package:** `c2/transport/` (add DoHTransport)
**MITRE:** T1071.004 — Application Layer Protocol: DNS
**Source:** gin-doh concepts (rewrite)
**Credit:** wcaszczxcey/gin-doh
**Refs:**
- https://github.com/wcaszczxcey/gin-doh

**API:**

```go
// NewDoH creates a DNS-over-HTTPS transport that encodes C2 data
// in DNS TXT queries via a DoH-compatible resolver.
func NewDoH(resolverURL string, domain string) *DoH
```

**Implementation:**
- Encode C2 data as DNS TXT record queries
- Send via HTTPS POST to DoH resolver (Cloudflare 1.1.1.1, Google 8.8.8.8)
- RFC 8484 compliant wire format
- Blends with legitimate DoH traffic

---

### 4.3 AV Arbitrary Delete via Symlink

**Package:** `evasion/avdelete/`
**MITRE:** T1562.001 — Impair Defenses: Disable or Modify Tools
**Source:** nixhacker blog + SymLinkExploit POC (rewrite)
**Credit:** nixhacker.com, shubham0d/Symbolic-link-exploitation
**Refs:**
- https://nixhacker.com/breaking-antivirus-arbitrary-delete-using-symbolic-link/
- https://github.com/shubham0d/Symbolic-link-exploitation/tree/master/SymLinkExploit

**API:**

```go
// DeleteViaAV exploits AV's real-time scanning to delete an arbitrary file.
// Creates an EICAR file, races to replace the parent directory with a junction
// pointing to the target. AV (running as SYSTEM) deletes the target.
func DeleteViaAV(targetPath string) error
```

---

## Sprint 5 (Weeks 9-10): Constructions avancees

### 5.1 PE/ELF Infector

**Package:** `pe/infect/`
**MITRE:** T1055.009 — Process Injection (via infected binary), T1195.002 — Supply Chain
**Source:** go-liora + Binject/binjection concepts (rewrite with our pe/parse)
**Credit:** guitmz/go-liora, Binject/binjection
**Refs:**
- https://github.com/guitmz/go-liora
- https://github.com/Binject/binjection

**API:**

```go
type InfectConfig struct {
    Payload    []byte           // Shellcode to inject
    Method     InfectionMethod  // Prepend, SectionInject, CodeCave, EntryPoint
    Marker     []byte           // Infection marker to avoid re-infection
}

// InfectPE infects a Windows PE file with the given payload.
func InfectPE(path string, cfg *InfectConfig) error

// InfectELF infects a Linux ELF file with the given payload.
func InfectELF(path string, cfg *InfectConfig) error
```

**Methods:**
- **Prepend** (go-liora style): prepend payload, adjust offsets
- **SectionInject**: add new section with shellcode, redirect entry point
- **CodeCave**: find padding in existing section, inject shellcode
- **EntryPoint**: patch entry point to jump to shellcode, then back to original

---

### 5.2 Reflective PE Loader

**Package:** `pe/reflective/`
**MITRE:** T1620 — Reflective Code Loading
**Source:** Binject/universal (fork + modernize) + carved4/meltloader concepts
**Credit:** Binject/universal, carved4
**Refs:**
- https://github.com/Binject/universal
- https://carved.lol/

**API:**

```go
// Load loads a PE/ELF/Mach-O from memory without using the OS loader.
// Performs manual mapping: section allocation, relocation, import resolution,
// TLS callbacks, entry point execution.
// Cross-platform: PE (Windows), ELF (Linux), Mach-O (macOS).
func Load(imageBytes []byte, caller *wsyscall.Caller) (*Library, error)

// Call invokes an exported function from a reflectively loaded library.
func (l *Library) Call(funcName string, args ...uintptr) (uintptr, error)

// LoadDLL loads a DLL from memory and returns a handle (Windows shorthand).
func LoadDLL(peBytes []byte, caller *wsyscall.Caller) (*Library, error)
```

---

### 5.3 RunAsVirtualAccount

**Package:** `win/impersonate/` (add to existing)
**MITRE:** T1134 — Access Token Manipulation
**Source:** gtworek/PSBits RunAsVA.c (rewrite)
**Credit:** gtworek/PSBits
**Refs:**
- https://github.com/gtworek/PSBits/blob/master/VirtualAccounts/RunAsVA.c

**API:**

```go
// RunAsVirtualAccount creates an ephemeral Windows Virtual Account,
// logs on as that identity, and runs the given command.
// Requires SeTcbPrivilege (SYSTEM).
func RunAsVirtualAccount(cmd string, args ...string) (*exec.Cmd, error)
```

---

## Sprint 6 (Weeks 11-12): Polish & Wiki

### 6.1 README Refactor

Slim README to ~60 lines:
- Title + badge + one-line description
- Install
- Quick Start (existing code block)
- Project Structure (existing tree)
- Acknowledgments (updated with all new credits)
- License
- Link to Wiki for all documentation

### 6.2 GitHub Wiki Migration

Move all `docs/` content to GitHub Wiki:
- `docs/techniques/*` → Wiki Techniques pages
- `docs/*.md` (API refs) → Wiki API pages
- `docs/examples/*` → Wiki Examples pages
- Keep `docs/` files as source, wiki is the rendered version
- Add a sync script or document manual sync process

### 6.3 Wallpaper

**Package:** `system/wallpaper/`
**Source:** reujab/wallpaper
**Credit:** reujab/wallpaper
**Refs:**
- https://github.com/reujab/wallpaper

```go
func Get() (string, error)
func Set(path string) error
```

### 6.4 Final Documentation Pass

- All new packages have doc.go with MITRE ID
- All technique docs added to wiki
- docs/mitre.md updated with new techniques
- Acknowledgments in README updated

---

## Dependency Graph

```
Sprint 1 (foundations)
  ├── system/ads/ ──────────── used by cleanup/selfdelete (improvement)
  ├── pe/srdi/ (go-donut) ─── used by inject/ (real shellcode gen)
  └── README refactor

Sprint 2 (evasion + CLR) — independent of Sprint 1
  ├── evasion/fakecmd/ ─────── uses win/ntapi
  ├── win/impersonate/ (TI) ── uses c2/shell.PPIDSpoofer pattern
  ├── evasion/hideprocess/ ─── uses win/ntapi
  ├── evasion/stealthopen/ ─── uses win/api
  ├── pe/clr/ ──────────────── CLR hosting, uses win/api + evasion/amsi
  ├── inject/ callbacks ────── extends existing
  └── win/token EnableAll ──── extends existing

Sprint 3 (collection) — independent of Sprint 1-2
  ├── collection/browser/ ──── standalone
  ├── collection/minidump/ ─── uses win/token, process/enum
  ├── collection/lsa/ ──────── uses win/token.StealByName
  ├── system/drivers/ ──────── uses pe/parse (authentihash)
  └── system/ads/ hidden ───── extends Sprint 1

Sprint 4 (transport) — independent
  ├── c2/transport/ pipe ───── new transport type
  ├── c2/transport/ doh ────── new transport type
  └── evasion/avdelete/ ────── standalone

Sprint 5 (advanced) — depends on Sprint 1 (pe/srdi, pe/parse)
  ├── pe/infect/ ───────────── uses pe/parse
  ├── pe/reflective/ ───────── uses pe/parse, win/ntapi
  └── win/impersonate/ VA ──── uses win/token

Sprint 6 (polish) — depends on all previous
  ├── Wiki migration
  ├── system/wallpaper/
  └── Final docs
```

## Acknowledgments to Add

| Source | Credit | Used In |
|--------|--------|---------|
| microsoft/go-winio | ADS + pipe concepts | system/ads/, c2/transport/ |
| Binject/go-donut + TheWover/donut | Shellcode generation algorithm | pe/srdi/ |
| gtworek/PSBits | FakeCmdLine, StealthOpen, LSA Dumper, RunAsVA, EnableAllPriv | evasion/, collection/, win/ |
| FourCoreLabs/LolDriverScan | Driver scanning concept | system/drivers/ |
| FourCoreLabs/TrustedInstallerPOC | TI impersonation pattern | win/impersonate/ |
| moonD4rk/HackBrowserData | Browser extraction concepts + crypto | collection/browser/ |
| C-Sto/gosecretsdump | SAM/LSA/NTDS.dit parsing (pure Go secretsdump) | collection/secrets/ |
| S3cur3Th1sSh1t | HideProcess + minidump callback | evasion/, collection/ |
| ropnop/go-clr | CLR hosting COM wrappers | pe/clr/ |
| OsandaMalith/CallbackShellcode | Additional callback methods | inject/ |
| guitmz/go-liora | ELF/PE infection concepts | pe/infect/ |
| nixhacker.com + shubham0d | Symlink AV delete | evasion/avdelete/ |
| wcaszczxcey/gin-doh | DoH transport concepts | c2/transport/ |
| reujab/wallpaper | Wallpaper get/set | system/wallpaper/ |
| loldrivers.io | Vulnerable driver database | system/drivers/ |
| Binject/universal + carved4 | Reflective loader (PE/ELF/Mach-O from memory) | pe/reflective/ |
| Binject/binjection | Binary injection/infection patterns | pe/infect/ |

## drivers.json Update Procedure

```bash
# Download latest loldrivers database
curl -o system/drivers/drivers.json https://www.loldrivers.io/api/drivers.json

# Verify size (should be ~4-8MB)
ls -lh system/drivers/drivers.json

# Rebuild to update embedded data
go build ./system/drivers/
```
