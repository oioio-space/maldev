//go:build linux

package runtime

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"crypto/rand"

	"golang.org/x/sys/unix"
)

// Linux x86_64 relocation types — see /usr/include/elf.h.
// Stage B handles only [rX8664Relative]; symbol-bound relocs
// (GLOB_DAT / JUMP_SLOT / 64) require Stage C's dynamic-symbol
// resolution and surface [ErrNotImplemented] until that lands.
const (
	rX8664None     = 0
	rX8664Reloc64  = 1
	rX8664Pc32     = 2
	rX8664GlobDat  = 6
	rX8664JumpSlot = 7
	rX8664Relative = 8
)

// Dynamic-section tag values used by the Linux loader. dtNull and
// dtNeeded are defined in elf.go (cross-platform); only the RELA
// tags are Linux-loader-specific.
const (
	dtRela    = 7
	dtRelaSz  = 8
	dtRelaEnt = 9
)

const (
	// fakeStackSize is the byte size of the kernel-style stack
	// mmap'd by Run() before transferring control. 256 KiB is
	// ample: Go's _rt0_amd64_linux + rt0_go switch to the g0
	// stack within hundreds of bytes of stack use; the rest is
	// headroom for auxv parsing and arch_prctl.
	fakeStackSize = 256 * 1024
)

// auxv type constants from <sys/auxv.h> / Linux elf(5). Only the
// entries that Run() needs to patch or zero are listed here.
const (
	atNull   = 0  // AT_NULL   — end of auxv vector
	atPhdr   = 3  // AT_PHDR   — address of the ELF program header table
	atPhent  = 4  // AT_PHENT  — size (bytes) of one Elf64_Phdr entry
	atPhnum  = 5  // AT_PHNUM  — number of program headers
	atEntry  = 9  // AT_ENTRY  — executable entry point (informational)
	atRandom = 25 // AT_RANDOM — address of 16 random bytes (stack canary)
)

// auxvEntry mirrors one Elf64_auxv_t (i64 a_type, u64 a_val).
type auxvEntry struct {
	Type uint64
	Val  uint64
}

// enterEntry swaps RSP to stackTop and JMPs to entry. Implemented
// in runtime_linux_amd64.s. Never returns.
//
//go:noescape
func enterEntry(entry, stackTop uintptr)

// rela64 mirrors Elf64_Rela. Field names track the ABI for
// greppability against /usr/include/elf.h.
type rela64 struct {
	Offset uint64 // r_offset — virtual address relative to image base
	Info   uint64 // r_info — packed (sym << 32) | type
	Addend int64  // r_addend — signed addend applied during relocation
}

func (r rela64) relType() uint32 { return uint32(r.Info & 0xFFFFFFFF) }
func (r rela64) relSym() uint32  { return uint32(r.Info >> 32) }

// mapAndRelocate is the Linux backend for PE inputs. PE on Linux
// is a format/host mismatch — operators must pack a Linux ELF
// when targeting a Linux host.
func mapAndRelocate(pe []byte, h *peHeaders) (*PreparedImage, error) {
	return nil, fmt.Errorf("%w: PE on Linux", ErrFormatPlatformMismatch)
}

// mapAndRelocateELF is the Linux backend for ELF inputs.
//
// Stage B coverage:
//   - Z-scope gate: only Go static-PIE binaries (ET_DYN, no
//     PT_INTERP, no DT_NEEDED, .go.buildinfo present) are
//     accepted. All others return ErrNotImplemented with the
//     reason from [elfHeaders.gateRejectionReason].
//   - PT_LOAD segments mmap'd into a single anonymous private
//     region (PROT_READ|PROT_WRITE during load, mprotect to
//     declared flags after relocations).
//   - File bytes copied per PT_LOAD; trailing .bss tail zeroed
//     by MAP_ANONYMOUS.
//   - Only ET_DYN (PIE / shared object) is mappable; ET_EXEC
//     returns ErrNotImplemented because reaching the linker-
//     fixed base via MAP_FIXED is operator-dangerous and modern
//     toolchains default to PIE anyway.
//   - PT_DYNAMIC walked for DT_RELA / DT_RELASZ / DT_RELAENT;
//     R_X86_64_RELATIVE relocs applied as `*(u64*)(base+offset) =
//     base + addend`. Symbol-bound relocs surface
//     ErrNotImplemented (Stage C territory).
//   - PT_INTERP: accepted when DT_NEEDED is absent. Go's
//     -buildmode=pie toolchain sets an interpreter path for
//     legacy ELF compatibility; without DT_NEEDED ld.so is
//     never invoked. We are the interpreter.
//   - PT_TLS: Go static-PIE binaries self-amorce TLS via
//     arch_prctl(ARCH_SET_FS) in their own _rt0, so no TLS init
//     is needed from the loader. No rejection needed here.
//
// Returns a [PreparedImage] with Base set to the mmap address
// (free via PreparedImage.Free → munmap). Run() still stubs to
// ErrNotImplemented; Stage D wires the jump-to-entry path.
func mapAndRelocateELF(elf []byte, h *elfHeaders) (*PreparedImage, error) {
	if !h.IsGoStaticPIE {
		return nil, fmt.Errorf("%w: %s", ErrNotImplemented, h.GateRejectionReason())
	}
	if h.ELFType != etDyn {
		return nil, fmt.Errorf("%w: ET_EXEC not supported (need PIE / ET_DYN)", ErrNotImplemented)
	}

	var (
		dynVAddr   uint64
		dynFileSz  uint64
		dynPresent bool
		spanEnd    uint64
	)
	for _, p := range h.Programs {
		switch p.Type {
		case ptLoad:
			end := p.VAddr + p.MemSz
			if end > spanEnd {
				spanEnd = end
			}
		case ptDynamic:
			dynVAddr = p.VAddr
			dynFileSz = p.FileSz
			dynPresent = true
		}
	}
	// PT_INTERP is allowed: Go's -buildmode=pie sets an interpreter
	// path even for static binaries with no DT_NEEDED. The gate in
	// detectGoStaticPIE already confirmed DT_NEEDED is absent, so
	// ld.so will never be invoked. We simply ignore the PT_INTERP
	// segment — our loader is the only interpreter needed.
	// No PT_DYNAMIC is valid for Go static-PIE binaries built with
	// -ldflags='-d' (Go internal linker omits the dynamic segment when
	// no interpreter is requested). The gate already accepted the binary
	// via dynamicHasNoNeeded, so no DT_NEEDED was present either.
	// Skip reloc processing in this case — there is nothing to relocate.

	pageSize := uint64(os.Getpagesize())
	mapSize := alignUp(spanEnd, pageSize)
	if mapSize == 0 {
		return nil, fmt.Errorf("%w: PT_LOAD span is empty", ErrBadELF)
	}

	region, err := unix.Mmap(-1, 0, int(mapSize),
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_ANONYMOUS|unix.MAP_PRIVATE)
	if err != nil {
		return nil, fmt.Errorf("packer/runtime: mmap(%d): %w", mapSize, err)
	}
	base := uintptr(unsafe.Pointer(&region[0]))

	// Copy PT_LOAD file content. .bss tail (MemSz > FileSz) is
	// already zeroed by MAP_ANONYMOUS.
	for _, p := range h.Programs {
		if p.Type != ptLoad || p.FileSz == 0 {
			continue
		}
		fileEnd := p.Offset + p.FileSz
		if fileEnd > uint64(len(elf)) || fileEnd < p.Offset {
			_ = unix.Munmap(region)
			return nil, fmt.Errorf("%w: PT_LOAD file range past end of input (%d > %d)",
				ErrBadELF, fileEnd, len(elf))
		}
		memEnd := p.VAddr + p.FileSz
		if memEnd > mapSize {
			_ = unix.Munmap(region)
			return nil, fmt.Errorf("%w: PT_LOAD vmem past mapped region (%d > %d)",
				ErrBadELF, memEnd, mapSize)
		}
		copy(region[p.VAddr:p.VAddr+p.FileSz], elf[p.Offset:fileEnd])
	}

	// Apply R_X86_64_RELATIVE relocations; refuse any other type
	// (Stage C will resolve them via ld.so). When no PT_DYNAMIC is
	// present the binary carries no relocation table by construction
	// (Go internal linker, -d flag, no ld.so), so skip the pass.
	if dynPresent {
		if reErr := applyRelativeRelocs(region, base, dynVAddr, dynFileSz); reErr != nil {
			_ = unix.Munmap(region)
			return nil, reErr
		}
	}

	// mprotect each PT_LOAD to its declared flags. Two adjacent
	// PT_LOAD segments that share a page would have one's mprotect
	// silently clobber the other's permissions; reject when a
	// segment's vaddr isn't page-aligned (real toolchains always
	// align PT_LOAD vaddrs to p_align ≥ pageSize).
	for _, p := range h.Programs {
		if p.Type != ptLoad {
			continue
		}
		if p.VAddr%pageSize != 0 {
			_ = unix.Munmap(region)
			return nil, fmt.Errorf("%w: PT_LOAD vaddr %#x not page-aligned", ErrBadELF, p.VAddr)
		}
		segStart := p.VAddr
		segEnd := alignUp(p.VAddr+p.MemSz, pageSize)
		if segEnd > mapSize {
			segEnd = mapSize
		}
		if err := unix.Mprotect(region[segStart:segEnd], protFromPF(p.Flags)); err != nil {
			_ = unix.Munmap(region)
			return nil, fmt.Errorf("packer/runtime: mprotect(%#x..%#x, flags=%#x): %w",
				segStart, segEnd, p.Flags, err)
		}
	}

	return &PreparedImage{
		Base:         base,
		SizeOfImage:  uint32(mapSize),
		EntryPoint:   base + uintptr(h.Entry),
		region:       region,
		elfPhdrOff:   h.Phoff,
		elfPhdrCount: uint64(h.Phnum),
		elfPhdrEnt:   uint64(h.Phentsize),
	}, nil
}

// applyRelativeRelocs walks the dynamic section, locates the
// RELA table, and applies every R_X86_64_RELATIVE relocation.
// Returns ErrNotImplemented when a non-RELATIVE entry is
// encountered (Stage C will route it through dlsym).
func applyRelativeRelocs(region []byte, base uintptr, dynVAddr, dynFileSz uint64) error {
	if dynFileSz < 16 {
		return fmt.Errorf("%w: PT_DYNAMIC too small (%d bytes)", ErrBadELF, dynFileSz)
	}
	if dynVAddr+dynFileSz > uint64(len(region)) || dynVAddr+dynFileSz < dynVAddr {
		return fmt.Errorf("%w: PT_DYNAMIC range past mapped region", ErrBadELF)
	}
	// Each Elf64_Dyn is 16 bytes: d_tag (i64) + d_val/d_ptr (u64).
	var (
		relaOff uint64
		relaSz  uint64
		relaEnt uint64 = 24 // sizeof(Elf64_Rela), default per ABI
	)
walk:
	for off := uint64(0); off+16 <= dynFileSz; off += 16 {
		tag := int64(binary.LittleEndian.Uint64(region[dynVAddr+off : dynVAddr+off+8]))
		val := binary.LittleEndian.Uint64(region[dynVAddr+off+8 : dynVAddr+off+16])
		switch tag {
		case dtNull:
			break walk
		case dtRela:
			relaOff = val
		case dtRelaSz:
			relaSz = val
		case dtRelaEnt:
			relaEnt = val
		}
	}
	if relaSz == 0 {
		// No relocations — nothing to do. PIE executables built
		// without external dependencies hit this path cleanly.
		return nil
	}
	if relaEnt != 24 {
		return fmt.Errorf("%w: DT_RELAENT=%d, expected 24", ErrBadELF, relaEnt)
	}
	if relaOff+relaSz > uint64(len(region)) {
		return fmt.Errorf("%w: RELA table past mapped region", ErrBadELF)
	}

	for off := relaOff; off+relaEnt <= relaOff+relaSz; off += relaEnt {
		rela := rela64{
			Offset: binary.LittleEndian.Uint64(region[off : off+8]),
			Info:   binary.LittleEndian.Uint64(region[off+8 : off+16]),
			Addend: int64(binary.LittleEndian.Uint64(region[off+16 : off+24])),
		}
		switch rela.relType() {
		case rX8664None:
			// no-op padding
		case rX8664Relative:
			if rela.Offset+8 > uint64(len(region)) {
				return fmt.Errorf("%w: RELATIVE r_offset %#x past mapped region",
					ErrBadELF, rela.Offset)
			}
			val := uint64(int64(base) + rela.Addend)
			binary.LittleEndian.PutUint64(region[rela.Offset:rela.Offset+8], val)
		default:
			return fmt.Errorf("%w: reloc type %d at offset %#x needs symbol resolution",
				ErrNotImplemented, rela.relType(), rela.Offset)
		}
	}
	return nil
}

// protFromPF maps an ELF program-header flags field (PF_X | PF_W
// | PF_R) to mmap PROT_* bits. PROT_NONE if no flag is set —
// usually a malformed PT_LOAD; mprotect will surface the error.
func protFromPF(flags uint32) int {
	prot := unix.PROT_NONE
	if flags&pfR != 0 {
		prot |= unix.PROT_READ
	}
	if flags&pfW != 0 {
		prot |= unix.PROT_WRITE
	}
	if flags&pfX != 0 {
		prot |= unix.PROT_EXEC
	}
	return prot
}

// alignUp rounds `v` up to a multiple of `align`. `align` must
// be a power of two — pageSize on Linux always is.
func alignUp(v, align uint64) uint64 { return (v + align - 1) &^ (align - 1) }

// readSelfAuxv reads /proc/self/auxv, parses the entries, and
// applies patches — a map from auxv type to new value — before
// returning. The trailing AT_NULL terminator is preserved.
//
// Callers must patch at minimum:
//   - AT_RANDOM (25): replace with address of fresh canary bytes
//     so the loaded binary doesn't share the parent's stack canary.
//   - AT_PHDR  (3):  replace with base + phdr_file_offset so the
//     loaded binary walks its own program headers, not the parent's.
//   - AT_PHENT (4):  replace with the loaded ELF's phentsize.
//   - AT_PHNUM (5):  replace with the loaded ELF's phnum.
//   - AT_ENTRY (9):  replace with the loaded binary's entry point.
func readSelfAuxv(patches map[uint64]uint64) ([]auxvEntry, error) {
	data, err := os.ReadFile("/proc/self/auxv")
	if err != nil {
		return nil, err
	}
	if len(data)%16 != 0 {
		return nil, fmt.Errorf("auxv length %d not a multiple of 16", len(data))
	}
	out := make([]auxvEntry, 0, len(data)/16)
	for off := 0; off+16 <= len(data); off += 16 {
		e := auxvEntry{
			Type: binary.LittleEndian.Uint64(data[off : off+8]),
			Val:  binary.LittleEndian.Uint64(data[off+8 : off+16]),
		}
		if v, ok := patches[e.Type]; ok {
			e.Val = v
		}
		out = append(out, e)
		if e.Type == atNull {
			return out, nil
		}
	}
	return nil, fmt.Errorf("auxv missing AT_NULL terminator")
}

// writeKernelFrame writes the Linux SysV-ABI process startup
// frame at the top of `stack`, mimicking what the kernel sets
// up for a freshly-execve'd binary. Returns the resulting RSP
// (16-byte aligned per x86_64 ABI; rsp -= padding when needed).
func writeKernelFrame(stack []byte, auxv []auxvEntry, canary [16]byte) uintptr {
	top := len(stack)
	canaryOff := top - 16
	copy(stack[canaryOff:top], canary[:])

	off := canaryOff
	for i := len(auxv) - 1; i >= 0; i-- {
		off -= 16
		binary.LittleEndian.PutUint64(stack[off:off+8], auxv[i].Type)
		binary.LittleEndian.PutUint64(stack[off+8:off+16], auxv[i].Val)
	}

	// argc/argv/envp sit below auxv. We need argc's address to be
	// 16-byte aligned so the loaded binary's _start sees a properly
	// aligned initial RSP. Align off DOWN first (before the three
	// 8-byte slots), not after, so the alignment gap falls between
	// the envp terminator and the auxv block — not between envp and
	// argc, which would corrupt the kernel-frame layout.
	//
	// After writing three 8-byte slots the alignment is:
	//   off_after_auxv (16-aligned) - 3*8 = off_after_auxv - 24
	// 24 % 16 == 8, so we need one extra 8-byte pad above the
	// argc slot to re-align. We insert it here by rounding off
	// down to the next 16-byte boundary, then stepping down 24.
	off &^= 0xF // align gap between auxv and envp NULL
	off -= 8
	binary.LittleEndian.PutUint64(stack[off:off+8], 0) // envp NULL
	off -= 8
	binary.LittleEndian.PutUint64(stack[off:off+8], 0) // argv NULL
	off -= 8
	binary.LittleEndian.PutUint64(stack[off:off+8], 0) // argc = 0

	return uintptr(unsafe.Pointer(&stack[off]))
}

// ReadSelfAuxvForTest exposes the auxv parser to runtime_test
// without leaking the auxvEntry type into the public API. Linux-
// only mirror of readSelfAuxv that accepts a single canaryPtr
// override (the common test case) and returns a typed pair slice
// the test package can iterate.
func ReadSelfAuxvForTest(canaryPtr uintptr) []struct {
	Type, Val uint64
} {
	patches := map[uint64]uint64{atRandom: uint64(canaryPtr)}
	entries, err := readSelfAuxv(patches)
	if err != nil {
		return nil
	}
	out := make([]struct{ Type, Val uint64 }, len(entries))
	for i, e := range entries {
		out[i] = struct{ Type, Val uint64 }{e.Type, e.Val}
	}
	return out
}

// Run jumps to the loaded image's entry point. ALWAYS gated by
// MALDEV_PACKER_RUN_E2E=1 — production callers must opt in
// explicitly. Returns once the entry point returns (most Go
// static-PIE binaries call exit_group, so this typically does
// NOT return).
//
// arch_prctl(ARCH_SET_FS) is per-thread on Linux, not per-process.
// LockOSThread pins this goroutine to a single OS thread for the JMP
// setup. Once the loaded binary's _rt0 issues arch_prctl(ARCH_SET_FS)
// the Go runtime's TLS view on this thread is broken — but the JMP is
// one-way and exit_group kills the whole process, so this thread never
// schedules another goroutine. No UnlockOSThread needed.
func (p *PreparedImage) Run() error {
	if os.Getenv("MALDEV_PACKER_RUN_E2E") != "1" {
		return errors.New("packer/runtime: PreparedImage.Run requires MALDEV_PACKER_RUN_E2E=1")
	}

	runtime.LockOSThread()

	stack, err := unix.Mmap(-1, 0, fakeStackSize,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("packer/runtime: fake stack mmap: %w", err)
	}

	var canary [16]byte
	if _, err := rand.Read(canary[:]); err != nil {
		_ = unix.Munmap(stack)
		runtime.UnlockOSThread()
		return fmt.Errorf("packer/runtime: AT_RANDOM canary: %w", err)
	}

	canaryPtr := uintptr(unsafe.Pointer(&stack[len(stack)-16]))

	// Patch the auxv entries that must reflect the loaded binary,
	// not the parent process:
	//   AT_PHDR  — program header table address (base + file offset)
	//   AT_PHENT — program header entry size
	//   AT_PHNUM — number of program headers
	//   AT_ENTRY — entry point of the loaded binary
	//   AT_RANDOM — fresh canary so the loaded runtime doesn't share
	//               the parent's stack canary seed
	patches := map[uint64]uint64{
		atPhdr:   uint64(p.Base) + p.elfPhdrOff,
		atPhent:  p.elfPhdrEnt,
		atPhnum:  p.elfPhdrCount,
		atEntry:  uint64(p.EntryPoint),
		atRandom: uint64(canaryPtr),
	}
	auxv, err := readSelfAuxv(patches)
	if err != nil {
		_ = unix.Munmap(stack)
		runtime.UnlockOSThread()
		return fmt.Errorf("packer/runtime: read /proc/self/auxv: %w", err)
	}

	stackTop := writeKernelFrame(stack, auxv, canary)
	enterEntry(p.EntryPoint, stackTop)
	return nil // unreachable on happy path — exit_group never returns
}

// Free munmaps the mapped image. Safe to call multiple times;
// only the first call frees, subsequent calls no-op.
func (p *PreparedImage) Free() error {
	if p.Base == 0 {
		return nil
	}
	err := unix.Munmap(p.region)
	p.Base = 0
	p.region = nil
	if err != nil {
		return fmt.Errorf("packer/runtime: munmap: %w", err)
	}
	return nil
}
