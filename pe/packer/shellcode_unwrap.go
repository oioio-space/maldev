package packer

import (
	"bytes"
	"debug/elf"
	"debug/pe"
	"errors"
	"fmt"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

// UnwrapShellcode is the symmetric reverse of [PackShellcode] for
// the PLAIN-wrap path (Encrypt=false). Given a runnable PE32+ or
// ELF64 produced by PackShellcode, it returns the raw shellcode
// bytes that sit at the entry point.
//
// Defender utility: lets cmd/packerscope and analysts extract the
// shellcode payload from a minimal-host-wrapped binary without
// running it. Symmetric to [transform.BuildMinimalPE32Plus] /
// [transform.BuildMinimalELF64WithSections]:
//
//	exe, _, _ := packer.PackShellcode(sc, packer.PackShellcodeOptions{
//	    Format: packer.FormatLinuxELF,
//	})
//	got, _ := packer.UnwrapShellcode(exe)   // got == sc
//
// Encrypted-wrap binaries (Encrypt=true) cannot be unwrapped here —
// the shellcode bytes are ciphertext at the entry point and the
// SGN-style stub does the runtime decryption with a per-pack key
// baked into the stub. Operators wanting that path use the symmetric
// `cmd/packerscope` flow with the AEAD key.
//
// Returns:
//   - shellcode bytes (slice into a copy — safe to retain after
//     `wrapped` is freed)
//   - [ErrNotMinimalWrap] when the input doesn't look like a
//     PackShellcode plain output (size mismatch, magic mismatch,
//     no .text section, or .text != entry-point body).
//   - [ErrUnsupportedFormat] when the input is neither PE32+ nor
//     ELF64.
func UnwrapShellcode(wrapped []byte) ([]byte, error) {
	switch transform.DetectFormat(wrapped) {
	case transform.FormatPE:
		return unwrapShellcodePE(wrapped)
	case transform.FormatELF:
		return unwrapShellcodeELF(wrapped)
	default:
		return nil, fmt.Errorf("%w: not a PE32+ or ELF64 input", ErrUnsupportedFormat)
	}
}

// ErrNotMinimalWrap fires when [UnwrapShellcode] receives a binary
// that parses as PE/ELF but doesn't match the minimal-host shape
// PackShellcode produces (e.g. a real Go binary, or an encrypted
// PackBinary output). The .text section bytes are not the operator's
// raw shellcode in that case.
var ErrNotMinimalWrap = errors.New("packer: not a minimal-host shellcode wrap")

func unwrapShellcodePE(input []byte) ([]byte, error) {
	f, err := pe.NewFile(bytes.NewReader(input))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotMinimalWrap, err)
	}
	defer f.Close()

	if len(f.Sections) != 1 {
		return nil, fmt.Errorf("%w: %d sections (minimal wrap has exactly 1 .text)", ErrNotMinimalWrap, len(f.Sections))
	}
	if f.Sections[0].Name != ".text" {
		return nil, fmt.Errorf("%w: section name %q != .text", ErrNotMinimalWrap, f.Sections[0].Name)
	}
	body, err := f.Sections[0].Data()
	if err != nil {
		return nil, fmt.Errorf("%w: read .text: %v", ErrNotMinimalWrap, err)
	}
	// .text Data() returns file-aligned bytes (zero-padded to
	// FileAlignment). VirtualSize is the actual code length.
	if vs := int(f.Sections[0].VirtualSize); vs > 0 && vs <= len(body) {
		body = body[:vs]
	}

	oh, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		return nil, fmt.Errorf("%w: not PE32+ optional header", ErrNotMinimalWrap)
	}
	// Entry must point to the start of .text — that's the minimal
	// wrap's contract. Anything else means we're looking at a real
	// binary or an encrypted PackBinary output.
	if uint64(oh.AddressOfEntryPoint) != uint64(f.Sections[0].VirtualAddress) {
		return nil, fmt.Errorf("%w: entry %#x != .text RVA %#x",
			ErrNotMinimalWrap, oh.AddressOfEntryPoint, f.Sections[0].VirtualAddress)
	}
	// Defensive copy so caller can free `input`.
	out := make([]byte, len(body))
	copy(out, body)
	return out, nil
}

func unwrapShellcodeELF(input []byte) ([]byte, error) {
	f, err := elf.NewFile(bytes.NewReader(input))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotMinimalWrap, err)
	}
	defer f.Close()

	textSec := f.Section(".text")
	if textSec == nil {
		return nil, fmt.Errorf("%w: no .text section", ErrNotMinimalWrap)
	}
	// Entry must be the first byte of .text — minimal-wrap contract.
	if f.FileHeader.Entry != textSec.Addr {
		return nil, fmt.Errorf("%w: e_entry %#x != .text Addr %#x",
			ErrNotMinimalWrap, f.FileHeader.Entry, textSec.Addr)
	}
	body, err := textSec.Data()
	if err != nil {
		return nil, fmt.Errorf("%w: read .text: %v", ErrNotMinimalWrap, err)
	}
	out := make([]byte, len(body))
	copy(out, body)
	return out, nil
}
