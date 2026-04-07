package cert

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// buildMinimalPE constructs the smallest valid PE (PE32+) with an empty
// security directory. The file has no sections and no certificate.
func buildMinimalPE(t *testing.T) []byte {
	t.Helper()

	// Layout:
	//   0x00: DOS header (64 bytes), e_lfanew at 0x3C = 0x40
	//   0x40: PE signature "PE\0\0"
	//   0x44: COFF header (20 bytes): 0 sections, opt header size = 112+16*8
	//   0x58: Optional header (PE32+): magic=0x20b, data dirs at +112
	//         Security dir (index 4) at +112+4*8 = +144 -> all zeros
	//   After optional header: nothing (no sections, no cert)

	const (
		dosHdrSize  = 0x40
		peOff       = dosHdrSize           // 0x40
		coffOff     = peOff + 4            // 0x44
		optOff      = coffOff + 20         // 0x58
		numDataDirs = 16                   // standard count
		optSize     = 112 + numDataDirs*8  // PE32+ optional header
		totalSize   = optOff + int(optSize)
	)

	buf := make([]byte, totalSize)

	// DOS header
	buf[0] = 'M'
	buf[1] = 'Z'
	binary.LittleEndian.PutUint32(buf[0x3C:], uint32(peOff))

	// PE signature
	copy(buf[peOff:], []byte("PE\x00\x00"))

	// COFF header: 0 sections, optional header size
	binary.LittleEndian.PutUint16(buf[coffOff+16:], uint16(optSize))

	// Optional header magic: PE32+ (0x20b)
	binary.LittleEndian.PutUint16(buf[optOff:], magic64)

	// NumberOfRvaAndSizes
	binary.LittleEndian.PutUint32(buf[optOff+108:], numDataDirs)

	return buf
}

// buildSignedPE creates a minimal PE with a fake certificate blob appended.
func buildSignedPE(t *testing.T) []byte {
	t.Helper()

	base := buildMinimalPE(t)

	// Fake WIN_CERTIFICATE: 8-byte header + 24 bytes of padding.
	fakeCert := make([]byte, 32)
	binary.LittleEndian.PutUint32(fakeCert[0:], 32)    // dwLength
	binary.LittleEndian.PutUint16(fakeCert[4:], 0x0200) // wRevision = WIN_CERT_REVISION_2_0
	binary.LittleEndian.PutUint16(fakeCert[6:], 0x0002) // wCertificateType = WIN_CERT_TYPE_PKCS_SIGNED_DATA

	certFileOffset := uint32(len(base))
	certSize := uint32(len(fakeCert))

	// Patch security directory entry.
	dirOff, err := securityDirOffset(base)
	if err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint32(base[dirOff:], certFileOffset)
	binary.LittleEndian.PutUint32(base[dirOff+4:], certSize)

	return append(base, fakeCert...)
}

func writeTempPE(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.exe")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadNoCert(t *testing.T) {
	path := writeTempPE(t, buildMinimalPE(t))

	_, err := Read(path)
	if !errors.Is(err, ErrNoCertificate) {
		t.Fatalf("expected ErrNoCertificate, got %v", err)
	}
}

func TestHasNoCert(t *testing.T) {
	path := writeTempPE(t, buildMinimalPE(t))

	ok, err := Has(path)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected Has to return false for unsigned PE")
	}
}

func TestReadAndExport(t *testing.T) {
	path := writeTempPE(t, buildSignedPE(t))

	c, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Raw) == 0 {
		t.Fatal("expected non-empty certificate data")
	}
	if len(c.Raw) != 32 {
		t.Fatalf("expected 32 bytes of cert data, got %d", len(c.Raw))
	}

	// Export and re-import round-trip.
	exportPath := filepath.Join(t.TempDir(), "cert.bin")
	if err := c.Export(exportPath); err != nil {
		t.Fatal(err)
	}

	imported, err := Import(exportPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(imported.Raw) != len(c.Raw) {
		t.Fatalf("round-trip size mismatch: %d vs %d", len(imported.Raw), len(c.Raw))
	}
}

func TestHasSigned(t *testing.T) {
	path := writeTempPE(t, buildSignedPE(t))

	ok, err := Has(path)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected Has to return true for signed PE")
	}
}

func TestStripAndHas(t *testing.T) {
	path := writeTempPE(t, buildSignedPE(t))

	// Strip in place.
	if err := Strip(path, ""); err != nil {
		t.Fatal(err)
	}

	ok, err := Has(path)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected Has to return false after Strip")
	}
}

func TestStripToDst(t *testing.T) {
	srcPath := writeTempPE(t, buildSignedPE(t))
	dstPath := filepath.Join(t.TempDir(), "stripped.exe")

	if err := Strip(srcPath, dstPath); err != nil {
		t.Fatal(err)
	}

	// Source still has cert.
	ok, err := Has(srcPath)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("source should still have certificate")
	}

	// Destination should not.
	ok, err = Has(dstPath)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("destination should not have certificate after strip")
	}
}

func TestCopy(t *testing.T) {
	signedPath := writeTempPE(t, buildSignedPE(t))
	unsignedPath := writeTempPE(t, buildMinimalPE(t))

	if err := Copy(signedPath, unsignedPath); err != nil {
		t.Fatal(err)
	}

	ok, err := Has(unsignedPath)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected unsigned PE to have certificate after Copy")
	}

	// Verify round-trip: read cert from both and compare size.
	orig, err := Read(signedPath)
	if err != nil {
		t.Fatal(err)
	}
	copied, err := Read(unsignedPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(orig.Raw) != len(copied.Raw) {
		t.Fatalf("cert size mismatch: %d vs %d", len(orig.Raw), len(copied.Raw))
	}
}

func TestWriteReplacesExisting(t *testing.T) {
	path := writeTempPE(t, buildSignedPE(t))

	// Create a different cert blob.
	newCert := &Certificate{Raw: make([]byte, 64)}
	binary.LittleEndian.PutUint32(newCert.Raw[0:], 64)
	binary.LittleEndian.PutUint16(newCert.Raw[4:], 0x0200)
	binary.LittleEndian.PutUint16(newCert.Raw[6:], 0x0002)

	if err := Write(path, newCert); err != nil {
		t.Fatal(err)
	}

	c, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Raw) != 64 {
		t.Fatalf("expected 64 bytes after Write, got %d", len(c.Raw))
	}
}

func TestReadInvalidPE(t *testing.T) {
	path := filepath.Join(t.TempDir(), "garbage.exe")
	if err := os.WriteFile(path, []byte("not a PE file"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Read(path)
	if !errors.Is(err, ErrInvalidPE) {
		t.Fatalf("expected ErrInvalidPE, got %v", err)
	}
}

func TestStripNoCert(t *testing.T) {
	path := writeTempPE(t, buildMinimalPE(t))

	err := Strip(path, "")
	if !errors.Is(err, ErrNoCertificate) {
		t.Fatalf("expected ErrNoCertificate, got %v", err)
	}
}
