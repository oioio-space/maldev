package transform_test

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

// buildMinimalPE constructs a synthetic PE32+ with one .text
// section. Returns bytes the transform package can parse.
//
// Layout: DOS header (0x40) | PE sig (4) | COFF (20) | Opt PE32+ (240) |
// 1 section header (40) | padding to file alignment | .text body
func buildMinimalPE(t *testing.T, opts minimalPEOpts) []byte {
	t.Helper()
	const (
		dosHdrSize = 0x40
		peSigSize  = 4
		coffSize   = 20
		optHdrSize = 240
	)
	if opts.NumSections == 0 {
		opts.NumSections = 1
	}
	if opts.TextSize == 0 {
		opts.TextSize = 0x100
	}
	if opts.OEPRVA == 0 {
		opts.OEPRVA = 0x1000 + 0x10 // mid-text
	}

	const fileAlign = 0x200
	const sectionAlign = 0x1000

	headersSize := dosHdrSize + peSigSize + coffSize + optHdrSize +
		int(opts.NumSections)*40
	headersAligned := alignUp(uint32(headersSize), fileAlign)

	textRVA := uint32(0x1000)
	textFileOff := headersAligned
	textRawSize := alignUp(opts.TextSize, fileAlign)

	totalSize := textFileOff + textRawSize
	out := make([]byte, totalSize)

	// DOS header
	out[0] = 'M'
	out[1] = 'Z'
	binary.LittleEndian.PutUint32(out[0x3C:0x40], dosHdrSize)

	// PE signature
	off := uint32(dosHdrSize)
	binary.LittleEndian.PutUint32(out[off:off+4], 0x00004550)
	off += peSigSize

	// COFF
	binary.LittleEndian.PutUint16(out[off:off+2], 0x8664) // Machine
	binary.LittleEndian.PutUint16(out[off+2:off+4], opts.NumSections)
	binary.LittleEndian.PutUint16(out[off+16:off+18], optHdrSize)
	binary.LittleEndian.PutUint16(out[off+18:off+20], 0x0022) // EXEC | LARGE_ADDR_AWARE
	off += coffSize

	// Optional Header PE32+
	binary.LittleEndian.PutUint16(out[off:off+2], 0x20B)
	binary.LittleEndian.PutUint32(out[off+0x10:off+0x14], opts.OEPRVA)
	binary.LittleEndian.PutUint64(out[off+0x18:off+0x20], 0x140000000)
	binary.LittleEndian.PutUint32(out[off+0x20:off+0x24], sectionAlign)
	binary.LittleEndian.PutUint32(out[off+0x24:off+0x28], fileAlign)
	binary.LittleEndian.PutUint16(out[off+0x30:off+0x32], 6) // MajorSubsystemVer
	binary.LittleEndian.PutUint32(out[off+0x38:off+0x3C], textRVA+textRawSize)
	binary.LittleEndian.PutUint32(out[off+0x3C:off+0x40], headersAligned)
	binary.LittleEndian.PutUint16(out[off+0x44:off+0x46], 3) // Subsystem CUI
	binary.LittleEndian.PutUint16(out[off+0x46:off+0x48], 0x0140) // DllChars
	binary.LittleEndian.PutUint64(out[off+0x48:off+0x50], 0x100000)
	binary.LittleEndian.PutUint64(out[off+0x50:off+0x58], 0x1000)
	binary.LittleEndian.PutUint64(out[off+0x58:off+0x60], 0x100000)
	binary.LittleEndian.PutUint64(out[off+0x60:off+0x68], 0x1000)
	binary.LittleEndian.PutUint32(out[off+0x6C:off+0x70], 16) // NumberOfRvaAndSizes
	if opts.TLSDirRVA != 0 {
		// Data directory [9] = TLS
		dirOff := off + 0x70 + 9*8
		binary.LittleEndian.PutUint32(out[dirOff:dirOff+4], opts.TLSDirRVA)
		binary.LittleEndian.PutUint32(out[dirOff+4:dirOff+8], 0x40)
	}
	off += optHdrSize

	// .text section header
	copy(out[off:off+8], []byte(".text\x00\x00\x00"))
	binary.LittleEndian.PutUint32(out[off+8:off+12], opts.TextSize)   // VirtualSize
	binary.LittleEndian.PutUint32(out[off+12:off+16], textRVA)        // VirtualAddress
	binary.LittleEndian.PutUint32(out[off+16:off+20], textRawSize)    // SizeOfRawData
	binary.LittleEndian.PutUint32(out[off+20:off+24], textFileOff)    // PointerToRawData
	binary.LittleEndian.PutUint32(out[off+36:off+40], 0x60000020)     // CODE | EXEC | READ
	return out
}

type minimalPEOpts struct {
	NumSections uint16
	TextSize    uint32
	OEPRVA      uint32
	TLSDirRVA   uint32
}

func alignUp(v, align uint32) uint32 {
	return (v + align - 1) &^ (align - 1)
}

func TestPlanPE_HappyPath(t *testing.T) {
	pe := buildMinimalPE(t, minimalPEOpts{TextSize: 0x500, OEPRVA: 0x1010})
	plan, err := transform.PlanPE(pe, 4096)
	if err != nil {
		t.Fatalf("PlanPE: %v", err)
	}
	if plan.Format != transform.FormatPE {
		t.Errorf("Format = %v, want PE", plan.Format)
	}
	if plan.TextRVA != 0x1000 {
		t.Errorf("TextRVA = %#x, want 0x1000", plan.TextRVA)
	}
	if plan.TextSize != 0x500 {
		t.Errorf("TextSize = %#x, want 0x500", plan.TextSize)
	}
	if plan.OEPRVA != 0x1010 {
		t.Errorf("OEPRVA = %#x, want 0x1010", plan.OEPRVA)
	}
	// Stub appended after .text — must be page-aligned
	if plan.StubRVA == 0 || plan.StubRVA%0x1000 != 0 {
		t.Errorf("StubRVA %#x not page-aligned", plan.StubRVA)
	}
	if plan.StubMaxSize != 4096 {
		t.Errorf("StubMaxSize = %d, want 4096", plan.StubMaxSize)
	}
}

func TestPlanPE_RejectsTLSCallbacks(t *testing.T) {
	pe := buildMinimalPE(t, minimalPEOpts{TLSDirRVA: 0x2000})
	_, err := transform.PlanPE(pe, 4096)
	if !errors.Is(err, transform.ErrTLSCallbacks) {
		t.Errorf("got %v, want ErrTLSCallbacks", err)
	}
}

func TestPlanPE_RejectsOEPOutsideText(t *testing.T) {
	pe := buildMinimalPE(t, minimalPEOpts{OEPRVA: 0x10000}) // way past .text
	_, err := transform.PlanPE(pe, 4096)
	if !errors.Is(err, transform.ErrOEPOutsideText) {
		t.Errorf("got %v, want ErrOEPOutsideText", err)
	}
}

func TestInjectStubPE_DebugPEParses(t *testing.T) {
	input := buildMinimalPE(t, minimalPEOpts{TextSize: 0x500, OEPRVA: 0x1010})
	plan, err := transform.PlanPE(input, 4096)
	if err != nil {
		t.Fatalf("PlanPE: %v", err)
	}
	encryptedText := bytes.Repeat([]byte{0xAA}, int(plan.TextSize))
	stubBytes := []byte{0x90, 0x90, 0xC3} // NOP NOP RET — minimal stub

	out, err := transform.InjectStubPE(input, encryptedText, stubBytes, plan)
	if err != nil {
		t.Fatalf("InjectStubPE: %v", err)
	}
	f, err := pe.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/pe rejected output: %v", err)
	}
	defer f.Close()

	if len(f.Sections) != 2 {
		t.Errorf("Sections = %d, want 2 (.text + new stub section)", len(f.Sections))
	}
	// Last section should be the new stub section
	stubSec := f.Sections[len(f.Sections)-1]
	if stubSec.VirtualAddress != plan.StubRVA {
		t.Errorf("stub section VA = %#x, want %#x", stubSec.VirtualAddress, plan.StubRVA)
	}
	// .text characteristics should now have MEM_WRITE bit set
	textSec := f.Sections[0]
	if textSec.Characteristics&0x80000000 == 0 {
		t.Error(".text Characteristics missing MEM_WRITE bit (RWX)")
	}
}

// TestInjectStubPE_HonoursTextMemSize verifies that setting Plan.TextMemSize >
// Plan.TextSize causes InjectStubPE to widen the .text VirtualSize in the output
// PE section header. The on-disk SizeOfRawData stays at the original TextSize —
// only the virtual window expands, giving the kernel-mapped zero gap that the
// in-place LZ4 inflate decoder needs as its decompression workspace.
func TestInjectStubPE_HonoursTextMemSize(t *testing.T) {
	const textSize = 0x500
	input := buildMinimalPE(t, minimalPEOpts{TextSize: textSize, OEPRVA: 0x1010})
	plan, err := transform.PlanPE(input, 4096)
	if err != nil {
		t.Fatalf("PlanPE: %v", err)
	}

	// Request double the on-disk size as virtual memory — simulates the
	// safety margin for LZ4 in-place inflate.
	plan.TextMemSize = plan.TextSize * 2

	encryptedText := bytes.Repeat([]byte{0xAA}, int(plan.TextSize))
	stubBytes := []byte{0x90, 0x90, 0xC3}

	out, err := transform.InjectStubPE(input, encryptedText, stubBytes, plan)
	if err != nil {
		t.Fatalf("InjectStubPE: %v", err)
	}

	f, err := pe.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/pe rejected output: %v", err)
	}
	defer f.Close()

	textSec := f.Sections[0]
	if textSec.VirtualSize != plan.TextMemSize {
		t.Errorf(".text VirtualSize = %#x, want TextMemSize %#x", textSec.VirtualSize, plan.TextMemSize)
	}
	// SizeOfRawData must stay at the file-aligned original text size — the
	// compressed payload is what lives on disk; the expanded virtual window
	// is kernel-zero-filled. PE spec §6.2: SizeOfRawData is rounded up to
	// FileAlignment (0x200 in the synthetic PE).
	const fileAlign = 0x200
	wantRaw := alignUp(textSize, fileAlign)
	if textSec.Size != wantRaw {
		t.Errorf(".text SizeOfRawData = %#x, want file-aligned TextSize %#x", textSec.Size, wantRaw)
	}
}

// TestInjectStubPE_TextMemSizeIgnoredWhenSmall confirms that setting
// Plan.TextMemSize <= Plan.TextSize is a no-op: the VirtualSize in the output
// section header is unchanged from the original input value.
func TestInjectStubPE_TextMemSizeIgnoredWhenSmall(t *testing.T) {
	const textSize = 0x500
	input := buildMinimalPE(t, minimalPEOpts{TextSize: textSize, OEPRVA: 0x1010})
	plan, err := transform.PlanPE(input, 4096)
	if err != nil {
		t.Fatalf("PlanPE: %v", err)
	}
	// Zero (default) and a value equal to TextSize must both be no-ops.
	for _, memSize := range []uint32{0, plan.TextSize} {
		plan.TextMemSize = memSize
		encryptedText := bytes.Repeat([]byte{0xAA}, int(plan.TextSize))
		stubBytes := []byte{0x90, 0xC3}
		out, err := transform.InjectStubPE(input, encryptedText, stubBytes, plan)
		if err != nil {
			t.Fatalf("TextMemSize=%d InjectStubPE: %v", memSize, err)
		}
		f, err := pe.NewFile(bytes.NewReader(out))
		if err != nil {
			t.Fatalf("debug/pe rejected: %v", err)
		}
		if f.Sections[0].VirtualSize != textSize {
			t.Errorf("TextMemSize=%d: VirtualSize=%#x, want original %#x",
				memSize, f.Sections[0].VirtualSize, textSize)
		}
		f.Close()
	}
}

func TestInjectStubPE_RejectsStubTooLarge(t *testing.T) {
	input := buildMinimalPE(t, minimalPEOpts{})
	plan, _ := transform.PlanPE(input, 16) // tiny budget
	encryptedText := bytes.Repeat([]byte{0xAA}, int(plan.TextSize))
	stubBytes := bytes.Repeat([]byte{0x90}, 100) // 100 > 16

	_, err := transform.InjectStubPE(input, encryptedText, stubBytes, plan)
	if !errors.Is(err, transform.ErrStubTooLarge) {
		t.Errorf("got %v, want ErrStubTooLarge", err)
	}
}
