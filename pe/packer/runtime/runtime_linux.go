//go:build linux

package runtime

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"unsafe"

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
//   - PT_INTERP rejected as a defensive guard (the Z-scope gate
//     already excludes it; this is a belt-and-suspenders check).
//   - PT_TLS: Go static-PIE binaries self-amorce TLS via
//     arch_prctl(ARCH_SET_FS) in their own _rt0, so no TLS init
//     is needed from the loader. No rejection needed here.
//
// Returns a [PreparedImage] with Base set to the mmap address
// (free via PreparedImage.Free → munmap). Run() still stubs to
// ErrNotImplemented; Stage D wires the jump-to-entry path.
func mapAndRelocateELF(elf []byte, h *elfHeaders) (*PreparedImage, error) {
	if !h.isGoStaticPIE {
		return nil, fmt.Errorf("%w: %s", ErrNotImplemented, h.gateRejectionReason())
	}
	if h.elfType != etDyn {
		return nil, fmt.Errorf("%w: ET_EXEC not supported (need PIE / ET_DYN)", ErrNotImplemented)
	}

	var (
		hasInterp  bool
		dynVAddr   uint64
		dynFileSz  uint64
		dynPresent bool
		spanEnd    uint64
	)
	for _, p := range h.programs {
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
		case ptInterp:
			hasInterp = true
		}
	}
	if hasInterp {
		// Reachable only if isGoStaticPIE detection has a bug; defensive.
		return nil, fmt.Errorf("%w: PT_INTERP requires ld.so resolution (Stage C)", ErrNotImplemented)
	}
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
	for _, p := range h.programs {
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
	for _, p := range h.programs {
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
		Base:        base,
		SizeOfImage: uint32(mapSize),
		EntryPoint:  base + uintptr(h.entry),
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

// Run is the Linux Run gate. Mirrors the Windows env-var contract
// so cross-platform operators can rely on the same opt-in. Stage D
// will replace the body with the actual jump-to-entry path.
func (p *PreparedImage) Run() error {
	if os.Getenv("MALDEV_PACKER_RUN_E2E") != "1" {
		return errors.New("packer/runtime: PreparedImage.Run requires MALDEV_PACKER_RUN_E2E=1")
	}
	return fmt.Errorf("%w: Linux ELF Run (Stage D)", ErrNotImplemented)
}

// Free munmaps the mapped image. Safe to call multiple times;
// only the first call frees, subsequent calls no-op.
func (p *PreparedImage) Free() error {
	if p.Base == 0 {
		return nil
	}
	region := unsafe.Slice((*byte)(unsafe.Pointer(p.Base)), p.SizeOfImage)
	err := unix.Munmap(region)
	p.Base = 0
	if err != nil {
		return fmt.Errorf("packer/runtime: munmap: %w", err)
	}
	return nil
}
