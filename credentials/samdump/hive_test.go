package samdump

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

// fakeReaderAt wraps a byte slice as an io.ReaderAt.
type fakeReaderAt struct{ b []byte }

func (f *fakeReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(f.b)) {
		return 0, io.EOF
	}
	n := copy(p, f.b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func TestReadHive_RejectsShortFile(t *testing.T) {
	_, err := readHive(&fakeReaderAt{b: []byte("regf")}, 4)
	if !errors.Is(err, ErrHiveCorrupt) {
		t.Fatalf("err = %v, want wrap of ErrHiveCorrupt", err)
	}
	if !strings.Contains(err.Error(), "shorter than REGF base block") {
		t.Errorf("error message lacks 'shorter than REGF': %v", err)
	}
}

func TestReadHive_RejectsBadMagic(t *testing.T) {
	body := make([]byte, regfBaseBlockSz)
	copy(body, []byte("XXXX")) // wrong magic
	_, err := readHive(&fakeReaderAt{b: body}, int64(len(body)))
	if !errors.Is(err, ErrHiveCorrupt) {
		t.Fatalf("err = %v, want wrap of ErrHiveCorrupt", err)
	}
	if !strings.Contains(err.Error(), "bad REGF magic") {
		t.Errorf("error message lacks 'bad REGF magic': %v", err)
	}
}

func TestReadHive_RejectsTooLarge(t *testing.T) {
	// We don't actually allocate 1+ GiB; readHive checks size before
	// reading. Pass a backed-by-empty ReaderAt so we don't need any
	// memory but get past the magic check failing first — since we
	// hit the size check first, this works.
	_, err := readHive(&fakeReaderAt{b: nil}, 1<<30+1)
	if !errors.Is(err, ErrHiveCorrupt) {
		t.Fatalf("err = %v, want wrap of ErrHiveCorrupt", err)
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("error message lacks 'too large': %v", err)
	}
}

// TestReadHive_AcceptsValidHeader builds a minimal REGF base block
// (no HBIN payload) and verifies that the header parse succeeds.
// Cell-tree traversal will fail because we don't ship an HBIN, but
// readHive itself should return cleanly.
func TestReadHive_AcceptsValidHeader(t *testing.T) {
	body := make([]byte, regfBaseBlockSz)
	copy(body, []byte(regfMagic))
	binary.LittleEndian.PutUint32(body[regfRootCellOff:regfRootCellOff+4], 0x20)

	h, err := readHive(&fakeReaderAt{b: body}, int64(len(body)))
	if err != nil {
		t.Fatalf("readHive: %v", err)
	}
	if h.rootCellOff != 0x20 {
		t.Errorf("rootCellOff = 0x%X, want 0x20", h.rootCellOff)
	}
	if h.hbinBaseOff != regfBaseBlockSz {
		t.Errorf("hbinBaseOff = 0x%X, want 0x%X", h.hbinBaseOff, regfBaseBlockSz)
	}
}

// TestCellAt_RejectsOutOfBoundsCell exercises the bounds check.
func TestCellAt_RejectsOutOfBoundsCell(t *testing.T) {
	body := make([]byte, regfBaseBlockSz)
	copy(body, []byte(regfMagic))
	binary.LittleEndian.PutUint32(body[regfRootCellOff:regfRootCellOff+4], 0x20)

	h, err := readHive(&fakeReaderAt{b: body}, int64(len(body)))
	if err != nil {
		t.Fatalf("readHive: %v", err)
	}
	_, err = h.cellAt(0x100000) // way past the file
	if !errors.Is(err, ErrHiveCorrupt) {
		t.Fatalf("err = %v, want wrap of ErrHiveCorrupt", err)
	}
}

func TestUtf16BytesToString(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{"empty", nil, ""},
		{"single-byte rejected", []byte{0x41}, ""},
		{"hello", []byte{'H', 0, 'e', 0, 'l', 0, 'l', 0, 'o', 0}, "Hello"},
		{"trailing nul stripped", []byte{'A', 0, 'B', 0, 0, 0}, "AB"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := utf16BytesToString(c.in); got != c.want {
				t.Errorf("utf16BytesToString(% X) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestExpandSubkeyList_RejectsUnknownTag exercises the subkey-index
// dispatch when given a malformed tag.
func TestExpandSubkeyList_RejectsUnknownTag(t *testing.T) {
	// Build a hive with a synthetic cell at a known offset whose
	// payload starts with "xx" + count=0.
	body := make([]byte, regfBaseBlockSz+0x100)
	copy(body, []byte(regfMagic))
	binary.LittleEndian.PutUint32(body[regfRootCellOff:regfRootCellOff+4], 0)

	// HBIN at 0x1000 — we don't validate hbin magic in the reader,
	// it goes straight from REGF root_offset to the cell at that
	// offset relative to 0x1000.
	cellOff := regfBaseBlockSz // file offset for the synthetic cell
	// Cell size header (negative = used) — make it 16 bytes total.
	const negSixteen = uint32(0xFFFFFFF0) // int32(-16) reinterpreted
	binary.LittleEndian.PutUint32(body[cellOff:cellOff+4], negSixteen)
	// Cell payload: "xx" tag + count=0 + filler.
	body[cellOff+4] = 'x'
	body[cellOff+5] = 'x'
	binary.LittleEndian.PutUint16(body[cellOff+6:cellOff+8], 0)

	h, err := readHive(&fakeReaderAt{b: body}, int64(len(body)))
	if err != nil {
		t.Fatalf("readHive: %v", err)
	}
	_, err = h.expandSubkeyList(0)
	if !errors.Is(err, ErrHiveCorrupt) {
		t.Fatalf("err = %v, want wrap of ErrHiveCorrupt", err)
	}
	if !strings.Contains(err.Error(), "unknown subkey-index type") {
		t.Errorf("error message lacks 'unknown subkey-index type': %v", err)
	}
}

// hiveBytesReader wraps bytes.Reader so we can satisfy io.ReaderAt
// in tests without re-implementing the wrapper.
func hiveBytesReader(b []byte) io.ReaderAt {
	return bytes.NewReader(b)
}

var _ = hiveBytesReader // silence unused warning when no positive-path tests reference it
