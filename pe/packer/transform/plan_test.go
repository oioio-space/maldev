package transform_test

import (
	"errors"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

func TestDetectFormat_PE(t *testing.T) {
	pe := []byte{'M', 'Z', 0, 0, 0, 0}
	if got := transform.DetectFormat(pe); got != transform.FormatPE {
		t.Errorf("got %v, want FormatPE", got)
	}
}

func TestDetectFormat_ELF(t *testing.T) {
	elf := []byte{0x7F, 'E', 'L', 'F', 0, 0}
	if got := transform.DetectFormat(elf); got != transform.FormatELF {
		t.Errorf("got %v, want FormatELF", got)
	}
}

func TestDetectFormat_Unknown(t *testing.T) {
	garbage := []byte{0, 0, 0, 0}
	if got := transform.DetectFormat(garbage); got != transform.FormatUnknown {
		t.Errorf("got %v, want FormatUnknown", got)
	}
}

func TestDetectFormat_TooShort(t *testing.T) {
	tiny := []byte{'M'}
	if got := transform.DetectFormat(tiny); got != transform.FormatUnknown {
		t.Errorf("got %v, want FormatUnknown for tiny input", got)
	}
}

func TestSentinels_AreErrorIs_Compatible(t *testing.T) {
	wrapped := transform.ErrNoTextSection
	if !errors.Is(wrapped, transform.ErrNoTextSection) {
		t.Error("ErrNoTextSection not its own root")
	}
}
