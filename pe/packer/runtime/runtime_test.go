package runtime_test

import (
	"errors"
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
