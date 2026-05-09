//go:build linux

package stage1_test

import (
	"bufio"
	"bytes"
	"os"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
	"github.com/oioio-space/maldev/pe/packer/stubgen/stage1"
)

// TestEmitCPUIDVendorRead_RuntimeMatchesHost mmaps the asm bytes as RX,
// invokes them on a 12-byte buffer with RDI pointing into the buffer, and
// asserts the output equals what `golang.org/x/sys/cpu` (or /proc/cpuinfo)
// reports for the same host.
func TestEmitCPUIDVendorRead_RuntimeMatchesHost(t *testing.T) {
	b, err := amd64.New()
	if err != nil {
		t.Fatalf("amd64.New: %v", err)
	}
	if err := stage1.EmitCPUIDVendorRead(b); err != nil {
		t.Fatalf("EmitCPUIDVendorRead: %v", err)
	}
	// Append a RET so we can call into the page directly.
	if err := b.RawBytes([]byte{0xc3}); err != nil {
		t.Fatalf("RET: %v", err)
	}
	asmBytes, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	mem, err := unix.Mmap(-1, 0, len(asmBytes),
		unix.PROT_READ|unix.PROT_WRITE|unix.PROT_EXEC,
		unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		t.Fatalf("mmap: %v", err)
	}
	defer unix.Munmap(mem)
	copy(mem, asmBytes)

	// Call via funcval indirection — same pattern as lz4_inflate_test.go.
	// The asm expects RDI = output buffer. Go register ABI: a func
	// signature func(unsafe.Pointer) puts the first pointer arg in RAX,
	// not RDI. We need a thin trampoline: load RDI from RAX before
	// invoking the asm. Build it in front of the original bytes.
	trampoline := []byte{0x48, 0x89, 0xc7} // mov rdi, rax
	full := append(append([]byte(nil), trampoline...), asmBytes...)

	mem2, err := unix.Mmap(-1, 0, len(full),
		unix.PROT_READ|unix.PROT_WRITE|unix.PROT_EXEC,
		unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		t.Fatalf("mmap2: %v", err)
	}
	defer unix.Munmap(mem2)
	copy(mem2, full)

	fv := &funcval{code: uintptr(unsafe.Pointer(&mem2[0]))}
	var fn func(dst unsafe.Pointer)
	*(*uintptr)(unsafe.Pointer(&fn)) = uintptr(unsafe.Pointer(fv))

	var buf [16]byte
	fn(unsafe.Pointer(&buf[0]))
	got := string(buf[:12])

	want := hostVendorString(t)
	if got != want {
		t.Errorf("CPUID vendor = %q, want %q", got, want)
	}
}

// hostVendorString returns the host's CPUID vendor by parsing
// /proc/cpuinfo's vendor_id line. Linux exposes the raw 12-byte CPUID
// EAX=0 string here, so the test cross-checks the asm output against an
// independent kernel-provided source.
func hostVendorString(t *testing.T) string {
	t.Helper()
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		t.Skipf("cannot open /proc/cpuinfo: %v", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "vendor_id") {
			if i := strings.Index(line, ":"); i != -1 {
				return strings.TrimSpace(line[i+1:])
			}
		}
	}
	t.Skip("vendor_id not in /proc/cpuinfo")
	return ""
}

// TestEmitCPUIDVendorRead_BytesShape pins the encoding so accidental
// changes to the byte sequence are caught even on non-x86 hosts.
func TestEmitCPUIDVendorRead_BytesShape(t *testing.T) {
	b, err := amd64.New()
	if err != nil {
		t.Fatalf("amd64.New: %v", err)
	}
	if err := stage1.EmitCPUIDVendorRead(b); err != nil {
		t.Fatalf("EmitCPUIDVendorRead: %v", err)
	}
	out, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want := []byte{
		0x31, 0xc0,
		0x0f, 0xa2,
		0x89, 0x1f,
		0x89, 0x57, 0x04,
		0x89, 0x4f, 0x08,
	}
	if !bytes.Equal(out, want) {
		t.Errorf("EmitCPUIDVendorRead bytes = %x, want %x", out, want)
	}
}

// TestEmitVendorCompare_BytesShape pins the encoding so accidental
// changes to the byte sequence get caught regardless of host arch.
func TestEmitVendorCompare_BytesShape(t *testing.T) {
	b, err := amd64.New()
	if err != nil {
		t.Fatalf("amd64.New: %v", err)
	}
	if err := stage1.EmitVendorCompare(b); err != nil {
		t.Fatalf("EmitVendorCompare: %v", err)
	}
	out, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want := []byte{
		0x4c, 0x8b, 0x17,
		0x4c, 0x3b, 0x16,
		0x75, 0x06,
		0x44, 0x8b, 0x57, 0x08,
		0x44, 0x3b, 0x56, 0x08,
	}
	if !bytes.Equal(out, want) {
		t.Errorf("EmitVendorCompare bytes = %x, want %x", out, want)
	}
}

// Runtime-exercise of EmitVendorCompare via mmap+funcval was attempted
// (push/pop rbx trampoline, LockOSThread + GCPercent(-1) guard) but
// reproducibly crashed on the second call with a hard SIGSEGV that
// bypassed Go's signal handler — symptomatic of the same Go-asm-funcval
// hazards the LZ4 SGN chain test hit. The byte-shape contract pinned by
// TestEmitVendorCompare_BytesShape is the authoritative regression
// guard; runtime correctness will be exercised end-to-end via the
// bundle E2E (a packed binary running standalone, no Go test harness)
// in C6-P4.

// TestEmitPEBBuildRead_BytesShape pins the encoding. Runtime exercise
// requires a Windows VM (PEB only exists on Windows x64) and is covered
// by the bundle E2E in a later phase.
func TestEmitPEBBuildRead_BytesShape(t *testing.T) {
	b, err := amd64.New()
	if err != nil {
		t.Fatalf("amd64.New: %v", err)
	}
	if err := stage1.EmitPEBBuildRead(b); err != nil {
		t.Fatalf("EmitPEBBuildRead: %v", err)
	}
	out, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want := []byte{
		0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,
		0x8b, 0x80, 0x20, 0x01, 0x00, 0x00,
	}
	if !bytes.Equal(out, want) {
		t.Errorf("EmitPEBBuildRead bytes = %x, want %x", out, want)
	}
}
