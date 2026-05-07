package host_test

import (
	"bytes"
	"debug/elf"
	"errors"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/stubgen/host"
)

func TestEmitELF_ParsesBackCleanly(t *testing.T) {
	stage1 := []byte{0x90, 0x90, 0xC3} // NOP NOP RET — minimal x64 valid code
	payload := bytes.Repeat([]byte{0xAA}, 256)

	out, err := host.EmitELF(host.ELFConfig{
		Stage1Bytes: stage1,
		PayloadBlob: payload,
	})
	if err != nil {
		t.Fatalf("EmitELF: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("EmitELF returned 0 bytes")
	}

	f, err := elf.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/elf rejected the emitted ELF: %v", err)
	}
	defer f.Close()

	if f.FileHeader.Class != elf.ELFCLASS64 {
		t.Errorf("Class = %v, want ELFCLASS64", f.FileHeader.Class)
	}
	if f.FileHeader.Data != elf.ELFDATA2LSB {
		t.Errorf("Data = %v, want ELFDATA2LSB", f.FileHeader.Data)
	}
	if f.FileHeader.Machine != elf.EM_X86_64 {
		t.Errorf("Machine = %v, want EM_X86_64", f.FileHeader.Machine)
	}
	if f.FileHeader.Type != elf.ET_DYN {
		t.Errorf("Type = %v, want ET_DYN (static-PIE)", f.FileHeader.Type)
	}

	// Count PT_LOAD program headers — expect exactly 2 (text + data).
	loadCount := 0
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD {
			loadCount++
		}
	}
	if loadCount != 2 {
		t.Errorf("PT_LOAD count = %d, want 2", loadCount)
	}

	// Entry point must fall within the first PT_LOAD's vaddr range.
	if len(f.Progs) > 0 {
		first := f.Progs[0]
		if f.FileHeader.Entry < first.Vaddr || f.FileHeader.Entry >= first.Vaddr+first.Memsz {
			t.Errorf("Entry %#x not within first PT_LOAD [%#x, %#x)",
				f.FileHeader.Entry, first.Vaddr, first.Vaddr+first.Memsz)
		}
	}
}

func TestEmitELF_RejectsEmptyStage1(t *testing.T) {
	_, err := host.EmitELF(host.ELFConfig{
		Stage1Bytes: nil,
		PayloadBlob: []byte{0xAA},
	})
	if !errors.Is(err, host.ErrEmptyStage1ELF) {
		t.Errorf("got %v, want ErrEmptyStage1ELF", err)
	}
}

func TestEmitELF_RejectsEmptyPayload(t *testing.T) {
	_, err := host.EmitELF(host.ELFConfig{
		Stage1Bytes: []byte{0x90, 0xC3},
		PayloadBlob: nil,
	})
	if !errors.Is(err, host.ErrEmptyPayloadELF) {
		t.Errorf("got %v, want ErrEmptyPayloadELF", err)
	}
}
