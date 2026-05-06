//go:build windows

package runtime

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// mapAndRelocate is the Windows backend for [Prepare]. Allocates
// SizeOfImage at the OS-chosen base, copies headers + sections,
// applies base relocations against the delta from preferred to
// actual base, resolves imports via LoadLibrary + GetProcAddress,
// then VirtualProtects each section to its declared characteristics.
func mapAndRelocate(pe []byte, h *peHeaders) (*PreparedImage, error) {
	base, err := windows.VirtualAlloc(0, uintptr(h.sizeOfImage),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE)
	if err != nil {
		return nil, fmt.Errorf("packer/runtime: VirtualAlloc(%d): %w", h.sizeOfImage, err)
	}

	img := &PreparedImage{
		Base:        base,
		SizeOfImage: h.sizeOfImage,
		EntryPoint:  base + uintptr(h.addressOfEntry),
	}
	mapped := unsafe.Slice((*byte)(unsafe.Pointer(base)), h.sizeOfImage)

	if int(h.sizeOfHeaders) > len(pe) {
		_ = windows.VirtualFree(base, 0, windows.MEM_RELEASE)
		return nil, fmt.Errorf("%w: SizeOfHeaders (%d) > input (%d)", ErrBadPE, h.sizeOfHeaders, len(pe))
	}
	copy(mapped[:h.sizeOfHeaders], pe[:h.sizeOfHeaders])

	for i := 0; i < int(h.numSections); i++ {
		s := readSection(pe, h, i)
		if s.SizeOfRawData == 0 {
			continue
		}
		end := int(s.PointerToRawData) + int(s.SizeOfRawData)
		if end > len(pe) {
			_ = windows.VirtualFree(base, 0, windows.MEM_RELEASE)
			return nil, fmt.Errorf("%w: section %q raw end (%d) > input (%d)",
				ErrBadPE, sectionName(s.Name), end, len(pe))
		}
		dstEnd := int(s.VirtualAddress) + int(s.SizeOfRawData)
		if dstEnd > int(h.sizeOfImage) {
			_ = windows.VirtualFree(base, 0, windows.MEM_RELEASE)
			return nil, fmt.Errorf("%w: section %q virtual end (%d) > SizeOfImage (%d)",
				ErrBadPE, sectionName(s.Name), dstEnd, h.sizeOfImage)
		}
		copy(mapped[s.VirtualAddress:dstEnd], pe[s.PointerToRawData:end])
	}

	delta := int64(base) - int64(h.imageBase)
	if delta != 0 {
		if err := applyRelocations(mapped, h, delta); err != nil {
			_ = windows.VirtualFree(base, 0, windows.MEM_RELEASE)
			return nil, err
		}
	}

	resolved, err := resolveImports(mapped, h)
	if err != nil {
		_ = windows.VirtualFree(base, 0, windows.MEM_RELEASE)
		return nil, err
	}
	img.Imports = resolved

	if err := protectSections(base, mapped, pe, h); err != nil {
		_ = windows.VirtualFree(base, 0, windows.MEM_RELEASE)
		return nil, err
	}

	return img, nil
}

// applyRelocations walks the .reloc directory and shifts every
// recorded address by `delta`. Supports IMAGE_REL_BASED_DIR64
// (the only common type on x64 PEs); other types are ignored
// per Microsoft's "loaders may skip unknown types" guidance.
func applyRelocations(mapped []byte, h *peHeaders, delta int64) error {
	dir := h.dataDirs[dirReloc]
	if dir.VirtualAddress == 0 || dir.Size == 0 {
		return nil
	}
	if int(dir.VirtualAddress)+int(dir.Size) > len(mapped) {
		return fmt.Errorf("%w: .reloc directory past mapped image", ErrBadPE)
	}
	block := dir.VirtualAddress
	end := dir.VirtualAddress + dir.Size

	for block < end {
		hdrEnd := int(block) + 8
		if hdrEnd > len(mapped) {
			return fmt.Errorf("%w: relocation block header past image", ErrBadPE)
		}
		pageRVA := binary.LittleEndian.Uint32(mapped[block : block+4])
		blockSize := binary.LittleEndian.Uint32(mapped[block+4 : block+8])
		if blockSize < 8 {
			return fmt.Errorf("%w: bogus reloc block size %d", ErrBadPE, blockSize)
		}
		entries := (blockSize - 8) / 2
		for i := uint32(0); i < entries; i++ {
			off := int(block) + 8 + int(i)*2
			if off+2 > len(mapped) {
				return fmt.Errorf("%w: reloc entry past image", ErrBadPE)
			}
			rec := binary.LittleEndian.Uint16(mapped[off : off+2])
			typ := rec >> 12
			rva := pageRVA + uint32(rec&0x0FFF)
			switch typ {
			case relTypeAbsolute:
				// Padding entry; skip.
			case relTypeDir64:
				patchOff := int(rva)
				if patchOff+8 > len(mapped) {
					return fmt.Errorf("%w: DIR64 patch past image", ErrBadPE)
				}
				orig := binary.LittleEndian.Uint64(mapped[patchOff : patchOff+8])
				binary.LittleEndian.PutUint64(mapped[patchOff:patchOff+8], orig+uint64(delta))
			default:
				// Unknown reloc type: skip per loader-tolerance
				// guidance. If this turns out to be an x64 PE
				// using HIGHLOW (rare), bail loudly here instead.
			}
		}
		block += blockSize
	}
	return nil
}

// resolveImports walks the import directory, LoadLibrary's each
// listed DLL, and patches the IAT with GetProcAddress results
// (or LookupFunctionByOrdinal when the high bit of the
// OriginalFirstThunk entry is set).
func resolveImports(mapped []byte, h *peHeaders) ([]ResolvedImport, error) {
	dir := h.dataDirs[dirImport]
	if dir.VirtualAddress == 0 || dir.Size == 0 {
		return nil, nil
	}
	var resolved []ResolvedImport
	descOff := int(dir.VirtualAddress)
	const descSize = 20

	for {
		if descOff+descSize > len(mapped) {
			return nil, fmt.Errorf("%w: import descriptor past image", ErrBadPE)
		}
		oft := binary.LittleEndian.Uint32(mapped[descOff : descOff+4])
		nameRVA := binary.LittleEndian.Uint32(mapped[descOff+12 : descOff+16])
		ftRVA := binary.LittleEndian.Uint32(mapped[descOff+16 : descOff+20])
		if nameRVA == 0 && ftRVA == 0 {
			break
		}
		dllName := readCString(mapped, int(nameRVA))
		hMod, err := windows.LoadLibrary(dllName)
		if err != nil {
			return nil, fmt.Errorf("packer/runtime: LoadLibrary(%q): %w", dllName, err)
		}

		thunkRVA := oft
		if thunkRVA == 0 {
			thunkRVA = ftRVA
		}
		iatOff := int(ftRVA)
		thunkOff := int(thunkRVA)
		for {
			if thunkOff+8 > len(mapped) || iatOff+8 > len(mapped) {
				return nil, fmt.Errorf("%w: thunk past image", ErrBadPE)
			}
			thunk := binary.LittleEndian.Uint64(mapped[thunkOff : thunkOff+8])
			if thunk == 0 {
				break
			}
			var addr uintptr
			imp := ResolvedImport{DLL: dllName}
			if thunk&0x8000000000000000 != 0 {
				ord := uint16(thunk & 0xFFFF)
				imp.Ordinal = ord
				p, err := windows.GetProcAddressByOrdinal(hMod, uintptr(ord))
				if err != nil {
					return nil, fmt.Errorf("packer/runtime: GetProcAddressByOrdinal(%s, %d): %w", dllName, ord, err)
				}
				addr = p
			} else {
				nameStart := int(thunk) + 2 // skip 2-byte hint
				fn := readCString(mapped, nameStart)
				imp.Function = fn
				p, err := windows.GetProcAddress(hMod, fn)
				if err != nil {
					return nil, fmt.Errorf("packer/runtime: GetProcAddress(%s!%s): %w", dllName, fn, err)
				}
				addr = p
			}
			imp.Address = addr
			binary.LittleEndian.PutUint64(mapped[iatOff:iatOff+8], uint64(addr))
			resolved = append(resolved, imp)
			thunkOff += 8
			iatOff += 8
		}
		descOff += descSize
	}
	return resolved, nil
}

// protectSections walks the section table again and calls
// VirtualProtect with the per-section protection bits derived
// from IMAGE_SECTION_HEADER.Characteristics.
//
// IMAGE_SCN_MEM_EXECUTE = 0x20000000
// IMAGE_SCN_MEM_READ    = 0x40000000
// IMAGE_SCN_MEM_WRITE   = 0x80000000
func protectSections(base uintptr, mapped, pe []byte, h *peHeaders) error {
	for i := 0; i < int(h.numSections); i++ {
		s := readSection(pe, h, i)
		size := s.VirtualSize
		if size == 0 {
			size = s.SizeOfRawData
		}
		if size == 0 {
			continue
		}
		exec := s.Characteristics&0x20000000 != 0
		read := s.Characteristics&0x40000000 != 0
		write := s.Characteristics&0x80000000 != 0
		var prot uint32
		switch {
		case exec && write:
			prot = windows.PAGE_EXECUTE_READWRITE
		case exec && read:
			prot = windows.PAGE_EXECUTE_READ
		case exec:
			prot = windows.PAGE_EXECUTE
		case write:
			prot = windows.PAGE_READWRITE
		case read:
			prot = windows.PAGE_READONLY
		default:
			prot = windows.PAGE_NOACCESS
		}
		var old uint32
		if err := windows.VirtualProtect(base+uintptr(s.VirtualAddress), uintptr(size), prot, &old); err != nil {
			return fmt.Errorf("packer/runtime: VirtualProtect(%q, 0x%x): %w",
				sectionName(s.Name), prot, err)
		}
	}
	return nil
}

// mapAndRelocateELF is the Windows backend for ELF inputs. ELF
// on Windows is a format/host mismatch — operators must pack a
// PE when targeting Windows.
func mapAndRelocateELF(elf []byte, h *elfHeaders) (*PreparedImage, error) {
	return nil, fmt.Errorf("%w: ELF on Windows", ErrFormatPlatformMismatch)
}

// Run jumps to the loaded image's entry point. ALWAYS gated by
// MALDEV_PACKER_RUN_E2E=1 — production callers must opt in
// explicitly. Returns once the entry point returns (most EXEs
// call ExitProcess, so this typically does NOT return).
func (p *PreparedImage) Run() error {
	if os.Getenv("MALDEV_PACKER_RUN_E2E") != "1" {
		return errors.New("packer/runtime: PreparedImage.Run requires MALDEV_PACKER_RUN_E2E=1")
	}
	syscall.SyscallN(p.EntryPoint)
	return nil
}

// Free releases the mapped image. Safe to call multiple times;
// only the first call frees, subsequent calls no-op. Caller
// must not touch [PreparedImage.Base] or any IAT pointer after
// Free returns.
func (p *PreparedImage) Free() error {
	if p.Base == 0 {
		return nil
	}
	err := windows.VirtualFree(p.Base, 0, windows.MEM_RELEASE)
	p.Base = 0
	return err
}

// readCString reads a NUL-terminated ASCII string from `mapped`
// starting at `off`. Returns "" on out-of-bounds or zero-length.
func readCString(mapped []byte, off int) string {
	if off < 0 || off >= len(mapped) {
		return ""
	}
	end := off
	for end < len(mapped) && mapped[end] != 0 {
		end++
	}
	return string(mapped[off:end])
}

// sectionName trims trailing zeros from the 8-byte name field.
func sectionName(b [8]byte) string {
	end := len(b)
	for end > 0 && b[end-1] == 0 {
		end--
	}
	return string(b[:end])
}
