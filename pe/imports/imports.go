package imports

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	saferpe "github.com/saferwall/pe"
)

// Import describes one IAT entry: which DLL it comes from + which
// function it resolves. ByOrdinal + Ordinal expose the
// ordinal-only import case that the previous debug/pe-backed
// implementation silently dropped (saferwall surfaces both halves).
type Import struct {
	DLL      string
	Function string // empty when ByOrdinal == true
	Ordinal  uint32 // valid when ByOrdinal == true
	ByOrdinal bool
	Hint     uint16 // index hint into the target's export name pointer table
}

// List returns every import resolved by the PE at pePath.
func List(pePath string) ([]Import, error) {
	data, err := os.ReadFile(pePath)
	if err != nil {
		return nil, fmt.Errorf("read PE: %w", err)
	}
	return FromBytes(data)
}

// ListByDLL returns every import the PE resolves through the named
// DLL. dllName matches case-insensitively (Windows convention).
func ListByDLL(pePath, dllName string) ([]Import, error) {
	all, err := List(pePath)
	if err != nil {
		return nil, err
	}
	var filtered []Import
	for _, imp := range all {
		if strings.EqualFold(imp.DLL, dllName) {
			filtered = append(filtered, imp)
		}
	}
	return filtered, nil
}

// FromReader parses a PE from an io.ReaderAt. Convenience for
// callers that already have the bytes in memory or via mmap.
func FromReader(r io.ReaderAt) ([]Import, error) {
	// saferwall's NewFile expects an *os.File. Drain the reader
	// into bytes when we don't have one.
	if rs, ok := r.(io.ReadSeeker); ok {
		if _, err := rs.Seek(0, io.SeekStart); err == nil {
			data, err := io.ReadAll(rs)
			if err != nil {
				return nil, fmt.Errorf("read: %w", err)
			}
			return FromBytes(data)
		}
	}
	return nil, errors.New("imports: FromReader requires an io.ReadSeeker (or use FromBytes)")
}

// FromBytes parses a PE from raw bytes.
func FromBytes(data []byte) ([]Import, error) {
	pf, err := saferpe.NewBytes(data, &saferpe.Options{
		// Imports-only fast path — skip everything we don't need.
		OmitExportDirectory:      true,
		OmitResourceDirectory:    true,
		OmitExceptionDirectory:   true,
		OmitSecurityDirectory:    true,
		OmitRelocDirectory:       true,
		OmitDebugDirectory:       true,
		OmitArchitectureDirectory: true,
		OmitGlobalPtrDirectory:   true,
		OmitTLSDirectory:         true,
		OmitLoadConfigDirectory:  true,
		OmitBoundImportDirectory: true,
		OmitIATDirectory:         true,
		OmitDelayImportDirectory: true,
		OmitCLRHeaderDirectory:   true,
		OmitCLRMetadata:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("parse PE: %w", err)
	}
	if err := pf.Parse(); err != nil {
		return nil, fmt.Errorf("parse PE directories: %w", err)
	}

	var out []Import
	for _, dll := range pf.Imports {
		for _, fn := range dll.Functions {
			out = append(out, Import{
				DLL:       dll.Name,
				Function:  fn.Name,
				Ordinal:   fn.Ordinal,
				ByOrdinal: fn.ByOrdinal,
				Hint:      fn.Hint,
			})
		}
	}
	return out, nil
}
