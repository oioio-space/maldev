//go:build linux

package runtime

import (
	"errors"
	"fmt"
	"os"
)

// mapAndRelocate is the Linux backend for PE inputs. PE on Linux
// is a format/host mismatch — operators must pack a Linux ELF
// when targeting a Linux host.
func mapAndRelocate(pe []byte, h *peHeaders) (*PreparedImage, error) {
	return nil, fmt.Errorf("%w: PE on Linux", ErrFormatPlatformMismatch)
}

// mapAndRelocateELF is the Linux backend for ELF inputs. Stage A
// of Phase 1f only ships the parser + dispatch wiring; the actual
// mmap + relocation + ld.so resolution lands in Stage B.
//
// Until Stage B lands the parsed [elfHeaders] are surfaced via a
// minimal [PreparedImage] (Base = 0, SizeOfImage = sum of PT_LOAD
// memsz, EntryPoint = h.entry) so tests can confirm the dispatch
// reached the Linux path.
func mapAndRelocateELF(elf []byte, h *elfHeaders) (*PreparedImage, error) {
	var sizeOfImage uint64
	for _, p := range h.programs {
		if p.Type != ptLoad {
			continue
		}
		end := p.VAddr + p.MemSz
		if end > sizeOfImage {
			sizeOfImage = end
		}
	}
	// Ship a "parsed but not mapped" image so callers can inspect
	// what would be loaded. The error tells operators not to
	// expect Run() to work yet.
	img := &PreparedImage{
		SizeOfImage: uint32(sizeOfImage),
		EntryPoint:  uintptr(h.entry),
	}
	return img, fmt.Errorf("%w: Linux ELF mapper (Stage B)", ErrNotImplemented)
}

// Run is the Linux Run gate. Mirrors the Windows env-var contract
// so cross-platform operators can rely on the same opt-in. Stage B
// will replace the body with the actual jump-to-entry path.
func (p *PreparedImage) Run() error {
	if os.Getenv("MALDEV_PACKER_RUN_E2E") != "1" {
		return errors.New("packer/runtime: PreparedImage.Run requires MALDEV_PACKER_RUN_E2E=1")
	}
	return fmt.Errorf("%w: Linux ELF Run (Stage D)", ErrNotImplemented)
}

// Free is a no-op on Linux until Stage B starts allocating.
func (p *PreparedImage) Free() error {
	return nil
}
