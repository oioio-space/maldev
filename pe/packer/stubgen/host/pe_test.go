package host_test

import (
	"bytes"
	"debug/pe"
	"errors"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/stubgen/host"
)

func TestEmitPE_ParsesBackCleanly(t *testing.T) {
	stage1 := []byte{0x90, 0x90, 0xC3} // NOP NOP RET — minimal valid x64 code
	payload := bytes.Repeat([]byte{0xAA}, 256)

	out, err := host.EmitPE(host.PEConfig{
		Stage1Bytes: stage1,
		PayloadBlob: payload,
	})
	if err != nil {
		t.Fatalf("EmitPE: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("EmitPE returned 0 bytes")
	}

	f, err := pe.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/pe.NewFile rejected the emitted PE: %v", err)
	}
	defer f.Close()

	if f.FileHeader.Machine != pe.IMAGE_FILE_MACHINE_AMD64 {
		t.Errorf("Machine = %#x, want %#x", f.FileHeader.Machine, pe.IMAGE_FILE_MACHINE_AMD64)
	}
	if len(f.Sections) != 2 {
		t.Fatalf("Sections = %d, want 2", len(f.Sections))
	}
	if f.Sections[0].Name != ".text" {
		t.Errorf("section 0 name = %q, want .text", f.Sections[0].Name)
	}
	if f.Sections[1].Name != ".maldev" {
		t.Errorf("section 1 name = %q, want .maldev", f.Sections[1].Name)
	}
}

func TestEmitPE_RejectsEmptyStage1(t *testing.T) {
	_, err := host.EmitPE(host.PEConfig{
		Stage1Bytes: nil,
		PayloadBlob: []byte{0xAA},
	})
	if !errors.Is(err, host.ErrEmptyStage1) {
		t.Errorf("got %v, want ErrEmptyStage1", err)
	}
}

func TestEmitPE_RejectsEmptyPayload(t *testing.T) {
	_, err := host.EmitPE(host.PEConfig{
		Stage1Bytes: []byte{0x90, 0xC3},
		PayloadBlob: nil,
	})
	if !errors.Is(err, host.ErrEmptyPayload) {
		t.Errorf("got %v, want ErrEmptyPayload", err)
	}
}
