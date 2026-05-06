package runtime

import (
	"errors"

	"github.com/oioio-space/maldev/pe/packer/internal/elfgate"
)

// ELF sentinels surfaced by [Prepare] when the input is an ELF
// binary. Aliased from elfgate so callers that imported
// packer/runtime can still errors.Is against them — the var
// identity is preserved via errors.Is wrapping.
var (
	// ErrBadELF fires on header-walk inconsistencies (truncated,
	// bad magic, impossible field values).
	ErrBadELF = elfgate.ErrBadELF

	// ErrUnsupportedELFArch fires when the ELF is not 64-bit
	// little-endian x86_64. 32-bit, big-endian, ARM64 are out
	// of scope.
	ErrUnsupportedELFArch = elfgate.ErrUnsupportedELFArch

	// ErrNotELFExec fires when the ELF type is neither ET_EXEC
	// nor ET_DYN. Object files (ET_REL), core files (ET_CORE),
	// and exotic types are out of scope.
	ErrNotELFExec = elfgate.ErrNotELFExec

	// ErrFormatPlatformMismatch fires when an ELF is fed to the
	// Windows backend or a PE to the Linux backend. Operators
	// must pack a host-matching binary.
	ErrFormatPlatformMismatch = errors.New("packer/runtime: format does not match host platform")

	// ErrNotImplemented fires for backends that exist but haven't
	// landed their map+relocate path yet.
	ErrNotImplemented = elfgate.ErrNotImplemented

	// ErrNotWindows fires from the long-tail stub on platforms
	// other than Windows / Linux. Defined cross-platform so test
	// code can compare against it via errors.Is regardless of
	// build host.
	ErrNotWindows = errors.New("packer/runtime: reflective loader not supported on this OS")
)

// ELF on-wire constants re-exported for runtime_linux.go and tests.
const (
	elfMagic0 = elfgate.ElfMagic0
	elfMagic1 = elfgate.ElfMagic1
	elfMagic2 = elfgate.ElfMagic2
	elfMagic3 = elfgate.ElfMagic3

	etDyn = 3 // ET_DYN — mirrored from elfgate for runtime.go / runtime_linux.go

	ptLoad    = 1             // PT_LOAD
	ptDynamic = 2             // PT_DYNAMIC
	ptInterp  = 3             // PT_INTERP
	ptTLS     = elfgate.PtTLS // PT_TLS

	pfX = 1 // PF_X
	pfW = 2 // PF_W
	pfR = 4 // PF_R

	// Dynamic-section tag values used by the Linux loader.
	// dtNull and dtNeeded are cross-platform (shared with elfgate);
	// re-declared here so runtime_linux.go doesn't import elfgate directly.
	dtNull   = 0 // DT_NULL
	dtNeeded = 1 // DT_NEEDED

	elfHeaderSize  = elfgate.ELFHeaderSize
	elfProgHdrSize = elfgate.ELFProgHdrSize
)

// elfHeaders aliases elfgate.ELFHeaders so runtime.go and
// runtime_linux.go don't need to import elfgate directly — that
// would create an import cycle because elfgate is already on the
// path pe/packer → elfgate, and pe/packer/runtime → pe/packer.
type elfHeaders = elfgate.ELFHeaders

// elfProgramHeader aliases elfgate.ELFProgramHeader for the same
// cycle-breaking reason.
type elfProgramHeader = elfgate.ELFProgramHeader

// parseELFHeaders delegates to elfgate so existing call-sites in
// runtime.go don't need changing.
func parseELFHeaders(in []byte) (*elfHeaders, error) {
	return elfgate.ParseELFHeaders(in)
}

// CheckELFLoadable returns nil when input is a Go static-PIE
// binary the Linux runtime can load, or an error explaining the
// rejection. Cross-platform — pure parse, no syscalls.
//
// Delegates to elfgate.CheckELFLoadable so the two packages share
// one implementation without an import cycle.
func CheckELFLoadable(input []byte) error {
	return elfgate.CheckELFLoadable(input)
}

