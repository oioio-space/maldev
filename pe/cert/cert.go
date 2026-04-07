package cert

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
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

	certOffset, certSize, err := findSecurityDir(data)
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
func Has(pePath string) (bool, error) {
	_, err := Read(pePath)
	if errors.Is(err, ErrNoCertificate) {
		return false, nil
	}
	return err == nil, err
}

// Strip removes the Authenticode certificate from a PE file and writes
// the result to dst. If dst is empty, the file is modified in place.
func Strip(pePath, dst string) error {
	data, err := os.ReadFile(pePath)
	if err != nil {
		return fmt.Errorf("read PE: %w", err)
	}

	certOffset, certSize, err := findSecurityDir(data)
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

	// Zero out the security directory entry.
	dirEntryOffset, err := securityDirOffset(data)
	if err != nil {
		return err
	}
	binary.LittleEndian.PutUint32(data[dirEntryOffset:], 0)   // VirtualAddress
	binary.LittleEndian.PutUint32(data[dirEntryOffset+4:], 0) // Size

	target := dst
	if target == "" {
		target = pePath
	}
	return os.WriteFile(target, data, 0o644)
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
// the security directory entry is patched to point to it.
func Write(pePath string, c *Certificate) error {
	if c == nil || len(c.Raw) == 0 {
		return ErrNoCertificate
	}

	data, err := os.ReadFile(pePath)
	if err != nil {
		return fmt.Errorf("read PE: %w", err)
	}

	// If the PE already has a certificate, truncate at the old offset.
	oldOffset, oldSize, err := findSecurityDir(data)
	if err != nil {
		return err
	}
	if oldOffset != 0 && oldSize != 0 {
		if int(oldOffset) > len(data) {
			return ErrInvalidPE
		}
		data = data[:oldOffset]
	}

	// Locate the security directory entry so we can patch it.
	dirEntryOffset, err := securityDirOffset(data)
	if err != nil {
		return err
	}

	// Append certificate at end of file.
	newOffset := uint32(len(data))
	newSize := uint32(len(c.Raw))

	binary.LittleEndian.PutUint32(data[dirEntryOffset:], newOffset)
	binary.LittleEndian.PutUint32(data[dirEntryOffset+4:], newSize)

	data = append(data, c.Raw...)

	return os.WriteFile(pePath, data, 0o644)
}

// Export saves the raw certificate data to a file.
func (c *Certificate) Export(path string) error {
	if c == nil || len(c.Raw) == 0 {
		return ErrNoCertificate
	}
	return os.WriteFile(path, c.Raw, 0o644)
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
// and returns the certificate file offset and size.
func findSecurityDir(data []byte) (offset, size uint32, err error) {
	entryOffset, err := securityDirOffset(data)
	if err != nil {
		return 0, 0, err
	}

	offset = binary.LittleEndian.Uint32(data[entryOffset:])
	size = binary.LittleEndian.Uint32(data[entryOffset+4:])
	return offset, size, nil
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
