package cert

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/oioio-space/maldev/evasion/stealthopen"
)

// Sentinel errors for certificate operations.
var (
	ErrNoCertificate = errors.New("PE file has no Authenticode certificate")
	ErrInvalidPE     = errors.New("invalid PE file")
)

// Certificate holds raw Authenticode certificate data extracted from a PE file.
type Certificate struct {
	Raw []byte // WIN_CERTIFICATE structure(s) including headers
}

// PE constants for navigating headers.
const (
	dosHeaderSize    = 0x40
	peSignatureSize  = 4
	coffHeaderSize   = 20
	securityDirIndex = 4 // IMAGE_DIRECTORY_ENTRY_SECURITY

	// Optional header magic values distinguish PE32 from PE32+.
	magic32 = 0x10b
	magic64 = 0x20b

	// Number of data directory entries before the security entry.
	// Each entry is 8 bytes (VirtualAddress + Size).
	dataDirEntrySize = 8
)

// Read extracts the Authenticode certificate from a PE file.
// Returns ErrNoCertificate if the file has no certificate.
func Read(pePath string) (*Certificate, error) {
	data, err := os.ReadFile(pePath)
	if err != nil {
		return nil, fmt.Errorf("read PE: %w", err)
	}

	certOffset, certSize, _, err := findSecurityDir(data)
	if err != nil {
		return nil, err
	}

	if certOffset == 0 && certSize == 0 {
		return nil, ErrNoCertificate
	}

	end := int(certOffset) + int(certSize)
	if end > len(data) || certOffset > uint32(len(data)) {
		return nil, ErrInvalidPE
	}

	raw := make([]byte, certSize)
	copy(raw, data[certOffset:end])

	return &Certificate{Raw: raw}, nil
}

// Has checks whether a PE file contains an Authenticode certificate.
// Only reads the PE headers (~1 KB), not the entire file.
func Has(pePath string) (bool, error) {
	f, err := os.Open(pePath)
	if err != nil {
		return false, fmt.Errorf("open PE: %w", err)
	}
	defer f.Close()

	// 1 KB is enough for DOS header + PE signature + COFF + optional header
	// + data directories on both PE32 and PE32+.
	buf := make([]byte, 1024)
	n, err := io.ReadAtLeast(f, buf, dosHeaderSize)
	if err != nil {
		return false, ErrInvalidPE
	}

	certOffset, certSize, _, err := findSecurityDir(buf[:n])
	if err != nil {
		return false, err
	}
	return certOffset != 0 || certSize != 0, nil
}

// Strip removes the Authenticode certificate from a PE file and writes
// the result to dst. If dst is empty, the file is modified in place.
// Equivalent to [StripVia] with a nil Creator.
func Strip(pePath, dst string) error {
	return StripVia(nil, pePath, dst)
}

// StripVia mirrors [Strip] but routes the final write through the
// operator-supplied [stealthopen.Creator]. nil falls back to a
// [stealthopen.StandardCreator] (plain os.Create).
func StripVia(creator stealthopen.Creator, pePath, dst string) error {
	data, err := os.ReadFile(pePath)
	if err != nil {
		return fmt.Errorf("read PE: %w", err)
	}

	certOffset, certSize, dirEntryOffset, err := findSecurityDir(data)
	if err != nil {
		return err
	}

	if certOffset == 0 && certSize == 0 {
		return ErrNoCertificate
	}

	// Truncate file data at the certificate offset.
	if int(certOffset) > len(data) {
		return ErrInvalidPE
	}
	data = data[:certOffset]

	// Zero out the security directory entry (offset was resolved once
	// by findSecurityDir — avoids double PE header parsing).
	binary.LittleEndian.PutUint32(data[dirEntryOffset:], 0)   // VirtualAddress
	binary.LittleEndian.PutUint32(data[dirEntryOffset+4:], 0) // Size

	// PE optional-header CheckSum is now stale — recompute so the
	// stripped image still verifies under ImageHlp!CheckSumMappedFile.
	if err := PatchPECheckSum(data); err != nil {
		return fmt.Errorf("patch checksum: %w", err)
	}

	target := dst
	if target == "" {
		target = pePath
	}
	return stealthopen.WriteAll(creator, target, data)
}

// Copy copies the Authenticode certificate from src PE to dst PE.
// The dst file must already exist. Its security directory is replaced.
func Copy(srcPE, dstPE string) error {
	c, err := Read(srcPE)
	if err != nil {
		return err
	}
	return Write(dstPE, c)
}


// Write writes raw certificate data to a PE file, replacing any existing
// certificate. The certificate blob is appended at the end of the file and
// the security directory entry is patched to point to it. Equivalent to
// [WriteVia] with a nil Creator.
func Write(pePath string, c *Certificate) error {
	return WriteVia(nil, pePath, c)
}

// WriteVia mirrors [Write] but routes the final write through the
// operator-supplied [stealthopen.Creator]. nil falls back to a
// [stealthopen.StandardCreator] (plain os.Create).
func WriteVia(creator stealthopen.Creator, pePath string, c *Certificate) error {
	if c == nil || len(c.Raw) == 0 {
		return ErrNoCertificate
	}

	data, err := os.ReadFile(pePath)
	if err != nil {
		return fmt.Errorf("read PE: %w", err)
	}

	// If the PE already has a certificate, truncate at the old offset.
	oldOffset, oldSize, dirEntryOffset, err := findSecurityDir(data)
	if err != nil {
		return err
	}
	if oldOffset != 0 && oldSize != 0 {
		if int(oldOffset) > len(data) {
			return ErrInvalidPE
		}
		data = data[:oldOffset]
	}

	// WIN_CERTIFICATE structures must be 8-byte aligned per PE spec.
	if pad := uint32(len(data)) % 8; pad != 0 {
		data = append(data, make([]byte, 8-pad)...)
	}

	// Append certificate at end of file.
	newOffset := uint32(len(data))
	newSize := uint32(len(c.Raw))

	binary.LittleEndian.PutUint32(data[dirEntryOffset:], newOffset)
	binary.LittleEndian.PutUint32(data[dirEntryOffset+4:], newSize)

	data = append(data, c.Raw...)

	// PE optional-header CheckSum is now stale — recompute so the
	// re-signed image still verifies under ImageHlp!CheckSumMappedFile.
	if err := PatchPECheckSum(data); err != nil {
		return fmt.Errorf("patch checksum: %w", err)
	}

	return stealthopen.WriteAll(creator, pePath, data)
}

// Export saves the raw certificate data to a file. Equivalent to
// [Certificate.ExportVia] with a nil Creator.
func (c *Certificate) Export(path string) error {
	return c.ExportVia(nil, path)
}

// ExportVia routes the certificate write through the operator-supplied
// [stealthopen.Creator]. nil falls back to a [stealthopen.StandardCreator]
// (plain os.Create).
func (c *Certificate) ExportVia(creator stealthopen.Creator, path string) error {
	if c == nil || len(c.Raw) == 0 {
		return ErrNoCertificate
	}
	return stealthopen.WriteAll(creator, path, c.Raw)
}

// Import loads raw certificate data from a file.
func Import(path string) (*Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, ErrNoCertificate
	}
	return &Certificate{Raw: data}, nil
}

// findSecurityDir locates the security directory entry in the PE data
// and returns the certificate file offset, size, and the byte offset of
// the directory entry itself (for patching by Strip/Write).
func findSecurityDir(data []byte) (certOffset, certSize, dirEntryOffset uint32, err error) {
	dirEntryOffset, err = securityDirOffset(data)
	if err != nil {
		return 0, 0, 0, err
	}

	certOffset = binary.LittleEndian.Uint32(data[dirEntryOffset:])
	certSize = binary.LittleEndian.Uint32(data[dirEntryOffset+4:])
	return certOffset, certSize, dirEntryOffset, nil
}

// securityDirOffset returns the byte offset within the PE data where the
// security directory entry (VirtualAddress field) is stored. This is needed
// to patch the entry when writing or stripping certificates.
func securityDirOffset(data []byte) (uint32, error) {
	if len(data) < dosHeaderSize {
		return 0, ErrInvalidPE
	}

	peOffset := binary.LittleEndian.Uint32(data[0x3C:])
	optHeaderStart := peOffset + peSignatureSize + coffHeaderSize
	if int(optHeaderStart)+2 > len(data) {
		return 0, ErrInvalidPE
	}

	magic := binary.LittleEndian.Uint16(data[optHeaderStart:])
	var dataDirStart uint32
	switch magic {
	case magic32:
		dataDirStart = optHeaderStart + 96
	case magic64:
		dataDirStart = optHeaderStart + 112
	default:
		return 0, ErrInvalidPE
	}

	secEntryStart := dataDirStart + securityDirIndex*dataDirEntrySize
	if int(secEntryStart)+dataDirEntrySize > len(data) {
		return 0, ErrInvalidPE
	}

	return secEntryStart, nil
}
