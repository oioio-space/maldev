package runtime_test

import (
	"errors"
	goruntime "runtime"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/runtime"
)

// TestPrepare_RejectsBadMagic feeds garbage and confirms the
// header parser bails before any allocation.
func TestPrepare_RejectsBadMagic(t *testing.T) {
	_, err := runtime.Prepare([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	if !errors.Is(err, runtime.ErrBadPE) {
		t.Errorf("Prepare(garbage): got %v, want ErrBadPE", err)
	}
}

func TestPrepare_RejectsTooShort(t *testing.T) {
	_, err := runtime.Prepare([]byte{0x4D, 0x5A})
	if !errors.Is(err, runtime.ErrBadPE) {
		t.Errorf("Prepare(2 bytes): got %v, want ErrBadPE", err)
	}
}

// TestPrepare_RejectsX86 builds a minimal-but-valid PE32 (32-bit)
// header and confirms the loader rejects it. We don't need the
// rest of the PE — parse fails on machine + optMagic checks long
// before section mapping.
func TestPrepare_RejectsX86(t *testing.T) {
	pe := buildHeaderOnlyPE(t, headerOpts{
		Machine: 0x14C, // I386
		OptMagic: 0x10B, // PE32
	})
	_, err := runtime.Prepare(pe)
	if !errors.Is(err, runtime.ErrUnsupportedArch) {
		t.Errorf("Prepare(x86): got %v, want ErrUnsupportedArch", err)
	}
}

// TestPrepare_RejectsDLL flips the IMAGE_FILE_DLL characteristic
// and confirms rejection.
func TestPrepare_RejectsDLL(t *testing.T) {
	pe := buildHeaderOnlyPE(t, headerOpts{
		Machine:         0x8664,
		OptMagic:        0x20B,
		Characteristics: 0x2000, // IMAGE_FILE_DLL
	})
	_, err := runtime.Prepare(pe)
	if !errors.Is(err, runtime.ErrNotEXE) {
		t.Errorf("Prepare(DLL): got %v, want ErrNotEXE", err)
	}
}

// TestPrepare_RejectsTLSCallbacks sets a non-zero TLS data
// directory and confirms rejection.
func TestPrepare_RejectsTLSCallbacks(t *testing.T) {
	pe := buildHeaderOnlyPE(t, headerOpts{
		Machine:  0x8664,
		OptMagic: 0x20B,
		TLSDir:   dirEntry{VirtualAddress: 0x1000, Size: 0x40},
	})
	_, err := runtime.Prepare(pe)
	if !errors.Is(err, runtime.ErrTLSCallbacks) {
		t.Errorf("Prepare(TLS): got %v, want ErrTLSCallbacks", err)
	}
}

// TestRun_GatedByEnvVar confirms PreparedImage.Run refuses to
// jump without MALDEV_PACKER_RUN_E2E=1, regardless of platform.
func TestRun_GatedByEnvVar(t *testing.T) {
	t.Setenv("MALDEV_PACKER_RUN_E2E", "")
	img := &runtime.PreparedImage{}
	if err := img.Run(); err == nil {
		t.Error("Run() returned nil — should refuse without env var")
	}
}

// TestFree_NoOpOnZeroBase confirms Free is safe to call on a
// zero-base image (the post-Free state, or a PreparedImage that
// never allocated).
func TestFree_NoOpOnZeroBase(t *testing.T) {
	img := &runtime.PreparedImage{}
	if err := img.Free(); err != nil {
		t.Errorf("Free() on zero-base: %v", err)
	}
}

// TestPrepare_RejectsTooShortInput exercises the < 4-byte guard
// the Prepare dispatcher trips before magic detection.
func TestPrepare_RejectsTooShortInput(t *testing.T) {
	_, err := runtime.Prepare([]byte{0x7F, 'E', 'L'})
	if !errors.Is(err, runtime.ErrBadPE) {
		t.Errorf("Prepare(3 bytes): got %v, want ErrBadPE", err)
	}
}

// TestPrepare_RejectsUnknownMagic confirms the dispatcher bails
// on input that's neither MZ nor \x7fELF.
func TestPrepare_RejectsUnknownMagic(t *testing.T) {
	_, err := runtime.Prepare([]byte{'X', 'Y', 'Z', 'W', 0, 0, 0, 0})
	if !errors.Is(err, runtime.ErrBadPE) {
		t.Errorf("Prepare(unknown magic): got %v, want ErrBadPE", err)
	}
}

// TestPrepare_ELF_RejectsNotELF64 covers the EI_CLASS guard.
func TestPrepare_ELF_RejectsNotELF64(t *testing.T) {
	elf := buildMinimalELF(t, elfHeaderOpts{Class: 1}) // ELF32
	_, err := runtime.Prepare(elf)
	if !errors.Is(err, runtime.ErrUnsupportedELFArch) {
		t.Errorf("Prepare(ELF32): got %v, want ErrUnsupportedELFArch", err)
	}
}

// TestPrepare_ELF_RejectsBigEndian covers the EI_DATA guard.
func TestPrepare_ELF_RejectsBigEndian(t *testing.T) {
	elf := buildMinimalELF(t, elfHeaderOpts{Data: 2})
	_, err := runtime.Prepare(elf)
	if !errors.Is(err, runtime.ErrUnsupportedELFArch) {
		t.Errorf("Prepare(BE): got %v, want ErrUnsupportedELFArch", err)
	}
}

// TestPrepare_ELF_RejectsNonX8664 covers the e_machine guard.
func TestPrepare_ELF_RejectsNonX8664(t *testing.T) {
	elf := buildMinimalELF(t, elfHeaderOpts{Machine: 183}) // EM_AARCH64
	_, err := runtime.Prepare(elf)
	if !errors.Is(err, runtime.ErrUnsupportedELFArch) {
		t.Errorf("Prepare(arm64): got %v, want ErrUnsupportedELFArch", err)
	}
}

// TestPrepare_ELF_RejectsRelocatable covers the e_type guard.
func TestPrepare_ELF_RejectsRelocatable(t *testing.T) {
	elf := buildMinimalELF(t, elfHeaderOpts{Type: 1}) // ET_REL
	_, err := runtime.Prepare(elf)
	if !errors.Is(err, runtime.ErrNotELFExec) {
		t.Errorf("Prepare(ET_REL): got %v, want ErrNotELFExec", err)
	}
}

// TestPrepare_ELF_RejectsNoLoad covers the "needs at least one
// PT_LOAD" guard — defensive against bogus phdr tables.
func TestPrepare_ELF_RejectsNoLoad(t *testing.T) {
	elf := buildMinimalELF(t, elfHeaderOpts{NoLoad: true})
	_, err := runtime.Prepare(elf)
	if !errors.Is(err, runtime.ErrBadELF) {
		t.Errorf("Prepare(no PT_LOAD): got %v, want ErrBadELF", err)
	}
}

// TestPrepare_ELF_RejectsTruncated covers the buffer-bounds guard
// when e_phoff + e_phnum*e_phentsize runs past the input.
func TestPrepare_ELF_RejectsTruncated(t *testing.T) {
	elf := buildMinimalELF(t, elfHeaderOpts{})
	_, err := runtime.Prepare(elf[:50]) // chop body
	if !errors.Is(err, runtime.ErrBadELF) {
		t.Errorf("Prepare(truncated): got %v, want ErrBadELF", err)
	}
}

// TestPrepare_ELF_BackendSurface confirms the dispatch reaches the
// platform-appropriate backend after a clean parse. Outcome varies
// by GOOS:
//
//   - linux   → ErrNotImplemented (Stage A) plus a non-nil
//     PreparedImage carrying the parsed entry / size.
//   - windows → ErrFormatPlatformMismatch (ELF on Windows is a
//     host mismatch).
//   - other   → ErrNotWindows (long-tail stub).
//
// This test pins the contract so Stage B can flip the linux arm
// to "no error, real Base" without regressing the other arms.
func TestPrepare_ELF_BackendSurface(t *testing.T) {
	elf := buildMinimalELF(t, elfHeaderOpts{Entry: 0x401000})
	img, err := runtime.Prepare(elf)
	switch goruntime.GOOS {
	case "linux":
		if !errors.Is(err, runtime.ErrNotImplemented) {
			t.Errorf("Prepare(elf) on linux: got %v, want ErrNotImplemented", err)
		}
		if img == nil {
			t.Fatal("Prepare(elf) on linux: got nil image, want parsed-but-not-mapped")
		}
		if img.EntryPoint != 0x401000 {
			t.Errorf("EntryPoint: got %#x, want 0x401000", img.EntryPoint)
		}
	case "windows":
		if !errors.Is(err, runtime.ErrFormatPlatformMismatch) {
			t.Errorf("Prepare(elf) on windows: got %v, want ErrFormatPlatformMismatch", err)
		}
	default:
		if !errors.Is(err, runtime.ErrNotWindows) {
			t.Errorf("Prepare(elf) on %s: got %v, want ErrNotWindows", goruntime.GOOS, err)
		}
	}
}

// TestPrepare_PE_OnLinux confirms PE on Linux returns the
// format/host mismatch sentinel — operators get a clear "wrong
// binary for this host" signal rather than a partial map.
func TestPrepare_PE_OnLinux(t *testing.T) {
	if goruntime.GOOS != "linux" {
		t.Skip("linux-only assertion; other platforms covered by the existing PE-rejection tests")
	}
	pe := buildHeaderOnlyPE(t, headerOpts{Machine: 0x8664, OptMagic: 0x20B})
	_, err := runtime.Prepare(pe)
	if !errors.Is(err, runtime.ErrFormatPlatformMismatch) {
		t.Errorf("Prepare(pe) on linux: got %v, want ErrFormatPlatformMismatch", err)
	}
}
