package transform_test

import (
	"context"
	"debug/elf"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

// exit42Shellcode is the 12-byte x86-64 Linux exit(42) sequence:
//
//	xor edi, edi    ; clear arg
//	mov dil, 42     ; arg = 42
//	mov eax, 60     ; sys_exit
//	syscall
//
// Hand-encoded to avoid a build-time as/ld dependency.
var exit42Shellcode = []byte{
	0x31, 0xff, // xor edi, edi
	0x40, 0xb7, 0x2a, // mov dil, 42
	0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60
	0x0f, 0x05, // syscall
}

// TestBuildMinimalELF64_RejectsEmpty pins the [transform.ErrMinimalELFCodeEmpty]
// sentinel.
func TestBuildMinimalELF64_RejectsEmpty(t *testing.T) {
	for _, c := range [][]byte{nil, {}} {
		_, err := transform.BuildMinimalELF64(c)
		if !errors.Is(err, transform.ErrMinimalELFCodeEmpty) {
			t.Errorf("BuildMinimalELF64(%v) = %v, want ErrMinimalELFCodeEmpty", c, err)
		}
	}
}

// TestBuildMinimalELF64_DebugELFParses asserts the Go stdlib's debug/elf
// reader accepts the produced bytes — a strong proxy for "the kernel
// will too" since debug/elf checks the same magic + structural fields.
func TestBuildMinimalELF64_DebugELFParses(t *testing.T) {
	out, err := transform.BuildMinimalELF64(exit42Shellcode)
	if err != nil {
		t.Fatalf("BuildMinimalELF64: %v", err)
	}
	if got, want := len(out), int(transform.MinimalELF64HeadersSize)+len(exit42Shellcode); got != want {
		t.Errorf("len(out) = %d, want %d", got, want)
	}

	f, err := elf.NewFile(bytesReader(out))
	if err != nil {
		t.Fatalf("debug/elf: %v", err)
	}
	defer f.Close()

	if f.Class != elf.ELFCLASS64 {
		t.Errorf("Class = %v, want ELFCLASS64", f.Class)
	}
	if f.Type != elf.ET_EXEC {
		t.Errorf("Type = %v, want ET_EXEC", f.Type)
	}
	if f.Machine != elf.EM_X86_64 {
		t.Errorf("Machine = %v, want EM_X86_64", f.Machine)
	}
	if got := len(f.Progs); got != 1 {
		t.Fatalf("len(Progs) = %d, want 1", got)
	}
	pt := f.Progs[0]
	if pt.Type != elf.PT_LOAD {
		t.Errorf("Progs[0].Type = %v, want PT_LOAD", pt.Type)
	}
	if pt.Flags != elf.PF_R|elf.PF_W|elf.PF_X {
		t.Errorf("Progs[0].Flags = %v, want PF_R|PF_W|PF_X", pt.Flags)
	}
	if pt.Vaddr != transform.MinimalELF64Vaddr {
		t.Errorf("Progs[0].Vaddr = %#x, want %#x", pt.Vaddr, transform.MinimalELF64Vaddr)
	}
	wantEntry := transform.MinimalELF64Vaddr + uint64(transform.MinimalELF64HeadersSize)
	if f.Entry != wantEntry {
		t.Errorf("Entry = %#x, want %#x", f.Entry, wantEntry)
	}
}

// TestBuildMinimalELF64_RunsExit42 is the SHIP GATE: writes the
// produced ELF to disk, executes it, asserts exit code 42. Validates
// the kernel actually loads the binary and runs the embedded shellcode.
func TestBuildMinimalELF64_RunsExit42(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("kernel ELF loader exercise — Linux only")
	}
	out, err := transform.BuildMinimalELF64(exit42Shellcode)
	if err != nil {
		t.Fatalf("BuildMinimalELF64: %v", err)
	}

	dir := t.TempDir()
	exe := filepath.Join(dir, "tiny")
	if err := os.WriteFile(exe, out, 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = exec.CommandContext(ctx, exe).Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("run %q: %v (not an ExitError; tiny ELF didn't load)", exe, err)
	}
	if got := exitErr.ExitCode(); got != 42 {
		t.Errorf("exit code = %d, want 42", got)
	}

	t.Logf("tiny ELF: %d bytes total (%d header + %d code), exit=42",
		len(out), transform.MinimalELF64HeadersSize, len(exit42Shellcode))
}

// bytesReader is a tiny io.ReaderAt-capable wrapper over a byte slice.
// debug/elf's NewFile wants ReaderAt, not Reader.
type byteSliceReader struct{ b []byte }

func bytesReader(b []byte) *byteSliceReader { return &byteSliceReader{b: b} }

func (r *byteSliceReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(r.b)) {
		return 0, errEOF
	}
	n := copy(p, r.b[off:])
	if n < len(p) {
		return n, errEOF
	}
	return n, nil
}

var errEOF = errors.New("EOF")
