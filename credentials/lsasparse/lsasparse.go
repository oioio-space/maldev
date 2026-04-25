package lsasparse

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// Sentinel errors. Callers use errors.Is to dispatch.
var (
	// ErrNotMinidump fires when the input does not start with the MDMP
	// signature — typically passed wrong file or truncated read.
	ErrNotMinidump = errors.New("lsasparse: input is not a MINIDUMP blob")

	// ErrUnsupportedBuild fires when the dump's BuildNumber doesn't
	// match any registered lsaTemplate. Operator can supply their own
	// via RegisterTemplate before retrying.
	ErrUnsupportedBuild = errors.New("lsasparse: no signature template for this build")

	// ErrLSASRVNotFound fires when lsasrv.dll isn't in the dump's
	// MODULE_LIST stream. Possible if the operator dumped the wrong
	// process or if the module-list capture failed.
	ErrLSASRVNotFound = errors.New("lsasparse: lsasrv.dll module not in MODULE_LIST")

	// ErrMSV1_0NotFound fires when msv1_0.dll isn't in MODULE_LIST.
	// Same diagnosis as ErrLSASRVNotFound but for the MSV provider.
	ErrMSV1_0NotFound = errors.New("lsasparse: msv1_0.dll module not in MODULE_LIST")

	// ErrKeyExtractFailed fires when pattern matching succeeded but
	// the decoded BCRYPT_KEY_DATA_BLOB header is malformed (bad magic,
	// impossible key length, …) — typically signals the wrong
	// template is in play even though BuildNumber matched.
	ErrKeyExtractFailed = errors.New("lsasparse: LSA crypto keys could not be extracted")
)

// Architecture identifies the dump's processor family. v1 ships x64
// only; ArchUnknown / ArchX86 reserve the slot for a future 32-bit
// variant.
type Architecture int

const (
	ArchUnknown Architecture = iota
	ArchX86
	ArchX64
)

// String returns a human-readable architecture name.
func (a Architecture) String() string {
	switch a {
	case ArchX86:
		return "x86"
	case ArchX64:
		return "x64"
	default:
		return "unknown"
	}
}

// LogonType mirrors the Windows LOGON_TYPE enum (winnt.h).
type LogonType uint32

const (
	LogonTypeUnknown           LogonType = 0
	LogonTypeInteractive       LogonType = 2
	LogonTypeNetwork           LogonType = 3
	LogonTypeBatch             LogonType = 4
	LogonTypeService           LogonType = 5
	LogonTypeUnlock            LogonType = 7
	LogonTypeNetworkClearText  LogonType = 8
	LogonTypeNewCredentials    LogonType = 9
	LogonTypeRemoteInteractive LogonType = 10
	LogonTypeCachedInteractive LogonType = 11
)

// String returns the LOGON32_LOGON_* friendly name (matches what an
// analyst sees in the Security event log).
func (lt LogonType) String() string {
	switch lt {
	case LogonTypeInteractive:
		return "Interactive"
	case LogonTypeNetwork:
		return "Network"
	case LogonTypeBatch:
		return "Batch"
	case LogonTypeService:
		return "Service"
	case LogonTypeUnlock:
		return "Unlock"
	case LogonTypeNetworkClearText:
		return "NetworkClearText"
	case LogonTypeNewCredentials:
		return "NewCredentials"
	case LogonTypeRemoteInteractive:
		return "RemoteInteractive"
	case LogonTypeCachedInteractive:
		return "CachedInteractive"
	default:
		return fmt.Sprintf("LogonType(%d)", uint32(lt))
	}
}

// Credential is the typed payload extracted for a single logon
// session. v1 ships exactly one variant: MSV1_0Credential. Future
// providers (Wdigest, Kerberos, TSPkg, CloudAP) implement this same
// interface so callers can range over Session.Credentials uniformly.
type Credential interface {
	// AuthPackage returns the Windows auth-package name —
	// "MSV1_0", "Wdigest", "Kerberos", "TSPkg", "CloudAP".
	AuthPackage() string
}

// LogonSession aggregates everything the parser knows about a single
// active session. Mirrors the shape pypykatz emits as JSON so external
// tools can consume our output via the same schema.
type LogonSession struct {
	LUID        uint64
	LogonType   LogonType
	UserName    string
	LogonDomain string
	LogonServer string
	LogonTime   time.Time
	SID         string
	Credentials []Credential
}

// Result aggregates the parse output.
type Result struct {
	BuildNumber  uint32
	Architecture Architecture
	Modules      []Module
	Sessions     []LogonSession
	Warnings     []string
}

// Wipe overwrites every credential byte buffer with zeros. Callers
// that hold a Result longer than the immediate decode-and-format
// cycle should call Wipe before discarding to limit the post-extract
// in-memory exposure window.
func (r *Result) Wipe() {
	if r == nil {
		return
	}
	for i := range r.Sessions {
		for j := range r.Sessions[i].Credentials {
			if w, ok := r.Sessions[i].Credentials[j].(interface{ wipe() }); ok {
				w.wipe()
			}
		}
	}
}

// Parse extracts credentials from a MINIDUMP blob. reader is read
// random-access via ReadAt; size is the total dump length so the
// parser can validate stream descriptors before dereferencing.
//
// Returns the typed Result on success. A dump from an unsupported
// build returns (partial Result, ErrUnsupportedBuild) — BuildNumber
// + Architecture + module list still come through so the caller can
// register a template and retry.
//
// Per-session decryption failures are non-fatal: they accumulate in
// Result.Warnings without aborting the walk.
func Parse(reader io.ReaderAt, size int64) (*Result, error) {
	r, err := openReader(reader, size)
	if err != nil {
		return nil, err
	}

	res := &Result{
		BuildNumber:  r.systemInfo.BuildNumber,
		Architecture: archFromMinidump(r.systemInfo.ProcessorArchitecture),
		Modules:      modulesFromReader(r),
	}

	// Find a template for this build. Missing template is non-fatal —
	// callers get build/architecture/modules and can RegisterTemplate
	// + Parse again.
	tmpl := templateFor(r.systemInfo.BuildNumber)
	if tmpl == nil {
		return res, fmt.Errorf("%w: build %d", ErrUnsupportedBuild, r.systemInfo.BuildNumber)
	}

	lsasrv, ok := res.ModuleByName("lsasrv.dll")
	if !ok {
		return res, ErrLSASRVNotFound
	}
	if _, ok := res.ModuleByName("msv1_0.dll"); !ok {
		// msv1_0.dll presence-check stays — it tells the caller the dump
		// covers the MSV provider even though the LogonSessionList head
		// itself lives in lsasrv. Future providers (NetLogon, …) may
		// branch on which auth-package DLLs are loaded.
		return res, ErrMSV1_0NotFound
	}

	keys, err := extractLSAKeys(r, lsasrv, tmpl)
	if err != nil {
		return res, err
	}

	sessions, warnings := extractMSV1_0(r, lsasrv, tmpl, keys)
	res.Warnings = append(res.Warnings, warnings...)

	// Wdigest is opt-in per Template (NodeSize=0 disables it). The
	// walker scans wdigest.dll, decrypts each session's password with
	// the same lsaKey chain, and merges results onto MSV sessions by
	// LUID. Sessions without an MSV match still surface — the caller
	// keeps everything it can extract.
	if wdigest, ok := res.ModuleByName("wdigest.dll"); ok {
		wdigCreds, wdigWarnings := extractWdigest(r, wdigest, tmpl, keys)
		sessions = mergeWdigest(sessions, wdigCreds)
		res.Warnings = append(res.Warnings, wdigWarnings...)
	}

	// DPAPI master-key cache lives in lsasrv.dll (already resolved
	// above for the LSA crypto step). Cached keys are pre-decrypted
	// — no lsaKey needed for this path. Same merge-by-LUID +
	// orphan-surface semantics as Wdigest.
	dpapiKeys, dpapiWarnings := extractDPAPI(r, lsasrv, tmpl)
	sessions = mergeDPAPI(sessions, dpapiKeys)
	res.Warnings = append(res.Warnings, dpapiWarnings...)

	// TSPkg (Terminal Services Package) lives in tspkg.dll and
	// caches plaintext RDP credentials. Same merge-by-LUID +
	// orphan-surface semantics as Wdigest.
	if tspkg, ok := res.ModuleByName("tspkg.dll"); ok {
		tsCreds, tsWarnings := extractTSPkg(r, tspkg, tmpl, keys)
		sessions = mergeTSPkg(sessions, tsCreds)
		res.Warnings = append(res.Warnings, tsWarnings...)
	}

	res.Sessions = sessions
	return res, nil
}

// ParseFile is a convenience wrapper that opens path and delegates to
// Parse. Closes the file before returning. Use Parse directly when
// the dump comes from memory (gzip-decompressed bytes, an exfil
// channel, etc.).
func ParseFile(path string) (*Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	return Parse(f, st.Size())
}

// archFromMinidump maps PROCESSOR_ARCHITECTURE_* (winnt.h) to our
// Architecture enum.
func archFromMinidump(pa uint16) Architecture {
	switch pa {
	case 0:
		return ArchX86
	case 9:
		return ArchX64
	default:
		return ArchUnknown
	}
}
