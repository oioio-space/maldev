package samdump

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
)

// Minimal Windows registry hive reader. Implements just enough of the
// MS-RegFile cell-based format to navigate SYSTEM and SAM hives by
// path and read NK class names + VK value data — the only operations
// the SAM-dump algorithm needs.
//
// What this reader supports:
//
//   - REGF base block (4096-byte signature + root-cell offset).
//   - HBIN block enumeration over the rest of the file.
//   - NK (Named Key) cells, class-name reads, subkey-list traversal.
//   - VK (Value Key) cells, inline + indirect data reads (≤ 4 bytes
//     vs. > 4 bytes).
//   - LF / LH / LI / RI subkey-index cells.
//
// What it intentionally skips:
//
//   - SK (security descriptor) cells — irrelevant to credential
//     extraction.
//   - DB (big-data) cells — only fires for values > 16344 bytes;
//     SAM/SYSTEM values are well under that.
//   - Hive write paths and dirty-cell tracking.
//   - Transaction log (LOG / LOG1 / LOG2) replay — operators staging
//     hives offline should `reg save` or VSS-copy a clean snapshot.

// ErrHiveCorrupt is returned when the hive file fails a structural
// invariant (bad magic, cell size out of bounds, unsupported cell
// type, …). The wrapped error carries the byte offset where the
// failure was detected.
var ErrHiveCorrupt = errors.New("samdump: hive structure corrupt")

// ErrHiveNotFound is returned when navigating a key path lands on a
// missing subkey or value.
var ErrHiveNotFound = errors.New("samdump: hive path not found")

// hive is a parsed registry hive backed by an in-memory copy of the
// hive file. SAM and SYSTEM are typically 16-32 MB so the whole-file
// load avoids per-cell I/O latency without strain.
type hive struct {
	body         []byte // entire hive file
	rootCellOff  int32  // offset (from end of REGF base block) of the root nk cell
	hbinBaseOff  int    // offset where the first HBIN starts (always 0x1000)
	originalRoot int32  // raw root_offset from REGF — kept for diagnostics
}

// REGF / HBIN constants per MS-RegFile.
const (
	regfMagic        = "regf"
	hbinMagic        = "hbin"
	regfBaseBlockSz  = 0x1000
	regfRootCellOff  = 0x24 // offset of root_cell_offset inside the base block
	hbinDataOff      = 0x20 // offset of cell data inside an HBIN
)

// Cell type constants (the 2-byte ASCII tag at the start of every
// cell payload).
const (
	cellTypeNK = "nk"
	cellTypeVK = "vk"
	cellTypeLF = "lf" // hash-leaf subkey list
	cellTypeLH = "lh" // hash-leaf, newer hash function
	cellTypeLI = "li" // plain-list subkey index
	cellTypeRI = "ri" // recursive index of LF/LH/LI cells
	cellTypeDB = "db" // big-data — not handled
)

// nkFlags and vkFlags bit positions consumed by this reader.
const (
	nkFlagCompressedName = 0x0020 // KeyName uses ASCII-as-Latin1, not UTF-16
	vkFlagCompressedName = 0x0001 // ValueName uses ASCII-as-Latin1
)

// VK data-type constants (only the ones the algorithm consumes).
const (
	regBinary    = 3
	regSZ        = 1
	regDWord     = 4
	regExpandSZ  = 2
	regMultiSZ   = 7
	regQWord     = 11
)

// readHive loads the entire hive into memory and validates the REGF
// base block. The returned *hive is ready for openKey / readValue.
func readHive(r io.ReaderAt, size int64) (*hive, error) {
	if size < regfBaseBlockSz {
		return nil, fmt.Errorf("%w: file shorter than REGF base block (%d bytes)", ErrHiveCorrupt, size)
	}
	if size > 1<<30 {
		return nil, fmt.Errorf("%w: hive too large (%d bytes; cap is 1 GiB)", ErrHiveCorrupt, size)
	}
	body := make([]byte, size)
	if _, err := r.ReadAt(body, 0); err != nil {
		return nil, fmt.Errorf("%w: read hive body: %v", ErrHiveCorrupt, err)
	}
	if string(body[0:4]) != regfMagic {
		return nil, fmt.Errorf("%w: bad REGF magic %q at offset 0", ErrHiveCorrupt, body[0:4])
	}
	root := int32(binary.LittleEndian.Uint32(body[regfRootCellOff : regfRootCellOff+4]))
	if root < 0 {
		return nil, fmt.Errorf("%w: negative root cell offset %d", ErrHiveCorrupt, root)
	}
	return &hive{
		body:         body,
		rootCellOff:  root,
		hbinBaseOff:  regfBaseBlockSz,
		originalRoot: root,
	}, nil
}

// cellAt returns the payload bytes of the cell whose offset (relative
// to the start of HBIN data — i.e., file offset minus 0x1000) is
// cellOff. The returned slice is the cell's user data (minus the
// 4-byte size header that prefixes every cell). Negative size = used
// cell (we ignore the sign for read), positive = free.
func (h *hive) cellAt(cellOff int32) ([]byte, error) {
	abs := h.hbinBaseOff + int(cellOff)
	if abs < 0 || abs+4 > len(h.body) {
		return nil, fmt.Errorf("%w: cell offset 0x%X out of bounds", ErrHiveCorrupt, cellOff)
	}
	rawSize := int32(binary.LittleEndian.Uint32(h.body[abs : abs+4]))
	size := int(rawSize)
	if size < 0 {
		size = -size
	}
	if size < 8 || abs+size > len(h.body) {
		return nil, fmt.Errorf("%w: cell @0x%X reports size %d (file len=%d)",
			ErrHiveCorrupt, cellOff, size, len(h.body))
	}
	return h.body[abs+4 : abs+size], nil
}

// rootKey returns the root NK cell of the hive.
func (h *hive) rootKey() (*nkCell, error) {
	return h.openCellNK(h.rootCellOff)
}

// nkCell is a parsed Named Key cell. Field set is restricted to what
// the SAM-dump algorithm consumes.
type nkCell struct {
	Flags          uint16
	Name           string
	ClassNameOff   int32
	ClassNameLen   uint16 // bytes (UTF-16, so divide by 2 for chars)
	SubkeyCount    uint32
	SubkeyListOff  int32
	ValueCount     uint32
	ValueListOff   int32
}

func (h *hive) openCellNK(cellOff int32) (*nkCell, error) {
	body, err := h.cellAt(cellOff)
	if err != nil {
		return nil, err
	}
	if len(body) < 0x4C {
		return nil, fmt.Errorf("%w: nk cell @0x%X too short (%d bytes)", ErrHiveCorrupt, cellOff, len(body))
	}
	if string(body[0:2]) != cellTypeNK {
		return nil, fmt.Errorf("%w: cell @0x%X has type %q, want nk", ErrHiveCorrupt, cellOff, body[0:2])
	}
	// CM_KEY_NODE layout (MS-RegFile + Microsoft kernel headers):
	//
	//	+0x00 Signature   'nk'
	//	+0x02 Flags
	//	+0x04 LastWriteTime  (8 bytes)
	//	+0x0C Spare         (4 bytes)
	//	+0x10 Parent        (4-byte HCELL_INDEX)
	//	+0x14 StableSubKeyCount    ← what we want (saved hives)
	//	+0x18 VolatileSubKeyCount  (always 0 in saved hives)
	//	+0x1C StableSubKeyList     ← list offset
	//	+0x20 VolatileSubKeyList   (always -1 in saved hives)
	//	+0x24 ValueCount
	//	+0x28 ValueList
	//	+0x2C Security
	//	+0x30 Class
	//	... +0x48 NameLength uint16, +0x4A ClassLength uint16
	//	+0x4C Name (variable)
	nk := &nkCell{
		Flags:         binary.LittleEndian.Uint16(body[2:4]),
		SubkeyCount:   binary.LittleEndian.Uint32(body[0x14:0x18]),
		SubkeyListOff: int32(binary.LittleEndian.Uint32(body[0x1C:0x20])),
		ValueCount:    binary.LittleEndian.Uint32(body[0x24:0x28]),
		ValueListOff:  int32(binary.LittleEndian.Uint32(body[0x28:0x2C])),
		ClassNameOff:  int32(binary.LittleEndian.Uint32(body[0x30:0x34])),
		ClassNameLen:  binary.LittleEndian.Uint16(body[0x4A:0x4C]),
	}
	nameLen := int(binary.LittleEndian.Uint16(body[0x48:0x4A]))
	if 0x4C+nameLen > len(body) {
		return nil, fmt.Errorf("%w: nk @0x%X name length %d overruns cell", ErrHiveCorrupt, cellOff, nameLen)
	}
	rawName := body[0x4C : 0x4C+nameLen]
	if nk.Flags&nkFlagCompressedName != 0 {
		nk.Name = string(rawName) // ASCII-as-Latin1
	} else {
		nk.Name = utf16BytesToString(rawName)
	}
	return nk, nil
}

// readClassName returns the NK cell's class-name bytes (UTF-16
// encoded; Microsoft stores boot-key fragments here as the ASCII
// representation of 4 hex chars).
func (h *hive) readClassName(nk *nkCell) (string, error) {
	if nk.ClassNameLen == 0 || nk.ClassNameOff <= 0 {
		return "", nil
	}
	body, err := h.cellAt(nk.ClassNameOff)
	if err != nil {
		return "", err
	}
	if int(nk.ClassNameLen) > len(body) {
		return "", fmt.Errorf("%w: class-name overruns cell @0x%X", ErrHiveCorrupt, nk.ClassNameOff)
	}
	return utf16BytesToString(body[:nk.ClassNameLen]), nil
}

// openSubkey returns the subkey of nk whose name matches (case-
// insensitive). Returns ErrHiveNotFound if the name is missing.
func (h *hive) openSubkey(nk *nkCell, name string) (*nkCell, error) {
	if nk.SubkeyCount == 0 || nk.SubkeyListOff <= 0 {
		return nil, fmt.Errorf("%w: subkey %q (parent has no subkeys)", ErrHiveNotFound, name)
	}
	offsets, err := h.expandSubkeyList(nk.SubkeyListOff)
	if err != nil {
		return nil, err
	}
	for _, off := range offsets {
		child, err := h.openCellNK(off)
		if err != nil {
			continue // skip malformed leaves rather than abort the walk
		}
		if strings.EqualFold(child.Name, name) {
			return child, nil
		}
	}
	return nil, fmt.Errorf("%w: subkey %q", ErrHiveNotFound, name)
}

// expandSubkeyList returns the flat list of NK cell offsets that the
// subkey-index at indexOff covers. Handles LF/LH/LI/RI cells.
func (h *hive) expandSubkeyList(indexOff int32) ([]int32, error) {
	body, err := h.cellAt(indexOff)
	if err != nil {
		return nil, err
	}
	if len(body) < 4 {
		return nil, fmt.Errorf("%w: index @0x%X too short", ErrHiveCorrupt, indexOff)
	}
	tag := string(body[0:2])
	count := int(binary.LittleEndian.Uint16(body[2:4]))
	switch tag {
	case cellTypeLF, cellTypeLH:
		// {NK_offset uint32, name_hint uint32} pairs.
		out := make([]int32, 0, count)
		for i := 0; i < count; i++ {
			off := 4 + i*8
			if off+4 > len(body) {
				return nil, fmt.Errorf("%w: %s @0x%X truncated at entry %d",
					ErrHiveCorrupt, tag, indexOff, i)
			}
			out = append(out, int32(binary.LittleEndian.Uint32(body[off:off+4])))
		}
		return out, nil
	case cellTypeLI:
		// uint32 NK offsets, no name hint.
		out := make([]int32, 0, count)
		for i := 0; i < count; i++ {
			off := 4 + i*4
			if off+4 > len(body) {
				return nil, fmt.Errorf("%w: li @0x%X truncated at entry %d", ErrHiveCorrupt, indexOff, i)
			}
			out = append(out, int32(binary.LittleEndian.Uint32(body[off:off+4])))
		}
		return out, nil
	case cellTypeRI:
		// Recursive — entries are offsets to other LF/LH/LI cells.
		var out []int32
		for i := 0; i < count; i++ {
			off := 4 + i*4
			if off+4 > len(body) {
				return nil, fmt.Errorf("%w: ri @0x%X truncated at entry %d", ErrHiveCorrupt, indexOff, i)
			}
			subOff := int32(binary.LittleEndian.Uint32(body[off : off+4]))
			subList, err := h.expandSubkeyList(subOff)
			if err != nil {
				return nil, err
			}
			out = append(out, subList...)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%w: unknown subkey-index type %q @0x%X",
			ErrHiveCorrupt, tag, indexOff)
	}
}

// vkCell is a parsed Value Key cell.
type vkCell struct {
	Name     string
	DataLen  uint32
	DataOff  int32
	DataType uint32
	Flags    uint16
}

func (h *hive) openCellVK(cellOff int32) (*vkCell, error) {
	body, err := h.cellAt(cellOff)
	if err != nil {
		return nil, err
	}
	if len(body) < 0x18 {
		return nil, fmt.Errorf("%w: vk @0x%X too short", ErrHiveCorrupt, cellOff)
	}
	if string(body[0:2]) != cellTypeVK {
		return nil, fmt.Errorf("%w: cell @0x%X has type %q, want vk", ErrHiveCorrupt, cellOff, body[0:2])
	}
	// CM_KEY_VALUE layout (MS-RegFile):
	//
	//	+0x00 Signature 'vk'   (2)
	//	+0x02 NameLength       (2)
	//	+0x04 DataLength       (4, high bit set = inline data)
	//	+0x08 DataOffset       (4, HCELL_INDEX)
	//	+0x0C Type             (4)
	//	+0x10 Flags            (2)
	//	+0x12 Spare            (2)
	//	+0x14 Name             (variable)
	nameLen := int(binary.LittleEndian.Uint16(body[2:4]))
	vk := &vkCell{
		DataLen:  binary.LittleEndian.Uint32(body[4:8]),
		DataOff:  int32(binary.LittleEndian.Uint32(body[8:12])),
		DataType: binary.LittleEndian.Uint32(body[12:16]),
		Flags:    binary.LittleEndian.Uint16(body[16:18]),
	}
	const nameOff = 0x14
	if nameOff+nameLen > len(body) {
		return nil, fmt.Errorf("%w: vk @0x%X name length %d overruns cell", ErrHiveCorrupt, cellOff, nameLen)
	}
	rawName := body[nameOff : nameOff+nameLen]
	if vk.Flags&vkFlagCompressedName != 0 {
		vk.Name = string(rawName)
	} else {
		vk.Name = utf16BytesToString(rawName)
	}
	return vk, nil
}

// readValue returns the named value's data bytes from nk. Returns
// ErrHiveNotFound if name is missing. The DWORD-size optimization
// (data ≤ 4 bytes stored inline in vk.DataOff) is honored — caller
// receives the bytes regardless of where they live.
func (h *hive) readValue(nk *nkCell, name string) ([]byte, *vkCell, error) {
	if nk.ValueCount == 0 || nk.ValueListOff <= 0 {
		return nil, nil, fmt.Errorf("%w: value %q (parent has no values)", ErrHiveNotFound, name)
	}
	listBody, err := h.cellAt(nk.ValueListOff)
	if err != nil {
		return nil, nil, err
	}
	if uint32(len(listBody)/4) < nk.ValueCount {
		return nil, nil, fmt.Errorf("%w: value list @0x%X shorter than %d entries",
			ErrHiveCorrupt, nk.ValueListOff, nk.ValueCount)
	}
	for i := uint32(0); i < nk.ValueCount; i++ {
		voff := int32(binary.LittleEndian.Uint32(listBody[i*4 : i*4+4]))
		vk, err := h.openCellVK(voff)
		if err != nil {
			continue
		}
		if !strings.EqualFold(vk.Name, name) {
			continue
		}
		// Inline-data optimization: when the data fits in 4 bytes,
		// Microsoft stores it directly in DataOff with the high bit of
		// DataLen set.
		const inlineFlag = 0x80000000
		realLen := vk.DataLen &^ inlineFlag
		if vk.DataLen&inlineFlag != 0 {
			out := make([]byte, realLen)
			binary.LittleEndian.PutUint32(make([]byte, 4), uint32(vk.DataOff))
			// vk.DataOff carries the 4 inline bytes as a little-endian uint32.
			var raw [4]byte
			binary.LittleEndian.PutUint32(raw[:], uint32(vk.DataOff))
			copy(out, raw[:realLen])
			return out, vk, nil
		}
		body, err := h.cellAt(vk.DataOff)
		if err != nil {
			return nil, nil, err
		}
		if uint32(len(body)) < realLen {
			return nil, nil, fmt.Errorf("%w: vk @0x%X data shorter than declared (%d < %d)",
				ErrHiveCorrupt, voff, len(body), realLen)
		}
		out := make([]byte, realLen)
		copy(out, body[:realLen])
		return out, vk, nil
	}
	return nil, nil, fmt.Errorf("%w: value %q", ErrHiveNotFound, name)
}

// openPath walks a backslash-delimited key path from the hive root.
// Empty path elements (e.g., a leading '\') are skipped. Returns
// ErrHiveNotFound if any segment is missing.
func (h *hive) openPath(path string) (*nkCell, error) {
	cur, err := h.rootKey()
	if err != nil {
		return nil, err
	}
	for _, seg := range strings.Split(path, `\`) {
		if seg == "" {
			continue
		}
		next, err := h.openSubkey(cur, seg)
		if err != nil {
			return nil, err
		}
		cur = next
	}
	return cur, nil
}

// utf16BytesToString decodes a little-endian UTF-16 byte slice into
// a Go string. Trailing NUL is trimmed if present.
func utf16BytesToString(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	codes := make([]uint16, len(b)/2)
	for i := range codes {
		codes[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	for len(codes) > 0 && codes[len(codes)-1] == 0 {
		codes = codes[:len(codes)-1]
	}
	return string(utf16.Decode(codes))
}
