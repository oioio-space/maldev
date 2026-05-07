package runtime_test

import (
	"errors"
	"os"
	goruntime "runtime"
	"strings"
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
//   - linux   → ErrNotImplemented (Stage B refuses ET_EXEC; only
//     PIE / ET_DYN is mappable until Stage C lands ld.so).
//   - windows → ErrFormatPlatformMismatch (ELF on Windows is a
//     host mismatch).
//   - other   → ErrNotWindows (long-tail stub).
//
// Pins the contract so Stage C can extend the linux arm
// (ET_EXEC stays rejected; ET_DYN + symbols resolves) without
// regressing the other arms.
func TestPrepare_ELF_BackendSurface(t *testing.T) {
	elf := buildMinimalELF(t, elfHeaderOpts{Entry: 0x401000})
	_, err := runtime.Prepare(elf)
	switch goruntime.GOOS {
	case "linux":
		if !errors.Is(err, runtime.ErrNotImplemented) {
			t.Errorf("Prepare(elf) on linux: got %v, want ErrNotImplemented", err)
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

// TestPrepare_ELF_RejectsETExecOnLinux pins Stage B's choice to
// only support PIE (ET_DYN). Modern toolchains default to PIE so
// this is rarely a real obstacle; the rejection surfaces clearly
// rather than failing later in the mmap path.
func TestPrepare_ELF_RejectsETExecOnLinux(t *testing.T) {
	if goruntime.GOOS != "linux" {
		t.Skip("Stage B is Linux-only; other GOOS arms covered by BackendSurface")
	}
	elf := buildMinimalELF(t, elfHeaderOpts{Type: 2}) // ET_EXEC
	_, err := runtime.Prepare(elf)
	if !errors.Is(err, runtime.ErrNotImplemented) {
		t.Errorf("Prepare(ET_EXEC) on linux: got %v, want ErrNotImplemented", err)
	}
}

// TestPrepare_ELF_ETExecGateIsFirst confirms that detectGoStaticPIE
// rejects ET_EXEC before checking DT_NEEDED or .go.buildinfo.
// A Go ET_EXEC binary (built without -buildmode=pie) has no
// DT_NEEDED, so without the ET_DYN check it would be falsely
// classified as static-PIE.
func TestPrepare_ELF_ETExecGateIsFirst(t *testing.T) {
	if goruntime.GOOS != "linux" {
		t.Skip("Stage B is Linux-only")
	}
	// ET_EXEC with no DT_NEEDED — the condition that previously
	// could have been misclassified as static-PIE before the
	// ET_DYN gate was added.
	elf := buildMinimalELF(t, elfHeaderOpts{Type: 2}) // ET_EXEC, no dynamic
	_, err := runtime.Prepare(elf)
	if !errors.Is(err, runtime.ErrNotImplemented) {
		t.Errorf("Prepare(ET_EXEC no-needed): got %v, want ErrNotImplemented", err)
	}
	// The rejection reason must identify ET_DYN as the blocker.
	if err != nil && !strings.Contains(err.Error(), "ET_DYN") {
		t.Errorf("rejection reason should mention ET_DYN; got: %v", err)
	}
}

// TestPrepare_ELF_InterpWithoutNeededIsNotRejectedForInterp confirms
// that PT_INTERP alone (no DT_NEEDED) no longer triggers an
// "ld.so required" rejection. Go's -buildmode=pie toolchain emits
// PT_INTERP even for fully static binaries. The operative check is
// DT_NEEDED: without it the interpreter is never invoked.
// TestStaticPIEGate_AcceptsInterpWithoutNeeded confirms the Stage E
// gate accepts ET_DYN binaries that carry PT_INTERP as long as no
// DT_NEEDED is present. Real Go static-PIE has both; the kernel
// only invokes ld.so when DT_NEEDED actually requests a library.
func TestStaticPIEGate_AcceptsInterpWithoutNeeded(t *testing.T) {
	elf := buildMinimalELF(t, elfHeaderOpts{Type: 3, WithInterp: true}) // ET_DYN + PT_INTERP, no DT_NEEDED
	if err := runtime.CheckELFLoadable(elf); err != nil {
		t.Errorf("CheckELFLoadable(PT_INTERP no DT_NEEDED): got %v, want nil", err)
	}
}

// TestStaticPIEGate_AcceptsTLSWithoutNeeded confirms PT_TLS no
// longer triggers a gate rejection. Static-PIE binaries (Go,
// musl, glibc -static-pie) self-amorce TLS in their own _start /
// _rt0; the loader never has to set up TLS itself.
func TestStaticPIEGate_AcceptsTLSWithoutNeeded(t *testing.T) {
	elf := buildMinimalELF(t, elfHeaderOpts{Type: 3, WithTLS: true}) // ET_DYN + PT_TLS, no DT_NEEDED
	if err := runtime.CheckELFLoadable(elf); err != nil {
		t.Errorf("CheckELFLoadable(PT_TLS no DT_NEEDED): got %v, want nil", err)
	}
}

// TestPrepare_ELF_AcceptsNoDynamicGoStaticPIE confirms ET_DYN +
// .go.buildinfo + no PT_DYNAMIC is accepted by the Stage B mapper.
// Go binaries built with -ldflags='-d' (internal linker, no ld.so)
// omit the dynamic segment entirely — the real hello_static_pie
// fixture is this shape. No PT_DYNAMIC means no relocation table,
// so the loader skips the reloc pass and proceeds to mprotect.
func TestPrepare_ELF_AcceptsNoDynamicGoStaticPIE(t *testing.T) {
	if goruntime.GOOS != "linux" {
		t.Skip("Stage B mapper is Linux-only")
	}
	elf := buildMinimalELF(t, elfHeaderOpts{Type: 3, WithGoBuildInfo: true})
	img, err := runtime.Prepare(elf)
	if err != nil {
		t.Fatalf("Prepare(ET_DYN no DYNAMIC + buildinfo): %v", err)
	}
	defer func() {
		if err := img.Free(); err != nil {
			t.Errorf("Free: %v", err)
		}
	}()
	if img.Base == 0 {
		t.Error("Base = 0 — mapper did not allocate")
	}
}

// TestPrepare_ELF_HappyPath_MinimalPIE_NoRelocs is the Stage B
// mapper smoke test: build the smallest valid PIE (ET_DYN +
// one PT_LOAD covering everything + one PT_DYNAMIC whose body
// is a 16-byte DT_NULL terminator), feed it through Prepare,
// and confirm the loader maps it cleanly. No relocations, no
// symbols — just exercises the mmap → copy → mprotect → return
// path. Run() is never called (still gated, still stub).
func TestPrepare_ELF_HappyPath_MinimalPIE_NoRelocs(t *testing.T) {
	if goruntime.GOOS != "linux" {
		t.Skip("Stage B mapper is Linux-only")
	}
	elf := buildMinimalELF(t, elfHeaderOpts{
		Type:            3, // ET_DYN
		Entry:           0x40,
		WithDynamic:     true,
		WithGoBuildInfo: true, // satisfy the Z-scope gate
	})
	img, err := runtime.Prepare(elf)
	if err != nil {
		t.Fatalf("Prepare(minimal PIE): %v", err)
	}
	defer func() {
		if err := img.Free(); err != nil {
			t.Errorf("Free(): %v", err)
		}
	}()
	if img.Base == 0 {
		t.Error("Base = 0; mapper did not allocate")
	}
	if img.SizeOfImage == 0 {
		t.Error("SizeOfImage = 0; mapper did not size the region")
	}
	if img.EntryPoint != img.Base+0x40 {
		t.Errorf("EntryPoint = %#x, want Base(%#x) + 0x40", img.EntryPoint, img.Base)
	}
}

// TestPreparedImage_FreeIdempotent confirms Free can be called
// twice without surfacing an error — operators may defer it
// even after an explicit cleanup path.
func TestPreparedImage_FreeIdempotent(t *testing.T) {
	if goruntime.GOOS != "linux" {
		t.Skip("Stage B mapper is Linux-only")
	}
	elf := buildMinimalELF(t, elfHeaderOpts{Type: 3, WithDynamic: true, WithGoBuildInfo: true})
	img, err := runtime.Prepare(elf)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := img.Free(); err != nil {
		t.Fatalf("first Free: %v", err)
	}
	if err := img.Free(); err != nil {
		t.Errorf("second Free: %v (expected no-op)", err)
	}
}

// TestPrepare_ELF_AcceptsRealGoStaticPIE loads the fixture binary
// from testdata, runs Prepare, and confirms the mapper succeeds
// without errors. Does NOT call Run() — that's gated behind the
// E2E test in runtime_e2e_linux_test.go.
func TestPrepare_ELF_AcceptsRealGoStaticPIE(t *testing.T) {
	if goruntime.GOOS != "linux" {
		t.Skip("Stage B mapper is Linux-only")
	}
	elf, err := os.ReadFile("testdata/hello_static_pie")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	img, err := runtime.Prepare(elf)
	if err != nil {
		t.Fatalf("Prepare(hello_static_pie): %v", err)
	}
	defer func() {
		if err := img.Free(); err != nil {
			t.Errorf("Free: %v", err)
		}
	}()
	if img.Base == 0 {
		t.Error("Base = 0 — mapper did not allocate")
	}
	if img.SizeOfImage == 0 {
		t.Error("SizeOfImage = 0")
	}
	if img.EntryPoint <= img.Base {
		t.Errorf("EntryPoint %#x not within mapped region (base %#x, size %d)",
			img.EntryPoint, img.Base, img.SizeOfImage)
	}
}

// TestPrepare_ELF_AcceptsRealNonGoStaticPIE exercises the Stage E
// mapper happy-path against the real hand-rolled asm fixture
// (testdata/hello_static_pie_c). Mirrors TestPrepare_ELF_AcceptsRealGoStaticPIE
// but for a non-Go binary — confirms the loader handles ELFs
// without any Go runtime metadata. Does NOT call Run(); the
// gated E2E covers that path.
func TestPrepare_ELF_AcceptsRealNonGoStaticPIE(t *testing.T) {
	if goruntime.GOOS != "linux" {
		t.Skip("Stage E mapper is Linux-only")
	}
	elf, err := os.ReadFile("testdata/hello_static_pie_c")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	img, err := runtime.Prepare(elf)
	if err != nil {
		t.Fatalf("Prepare(hello_static_pie_c): %v", err)
	}
	defer func() {
		if err := img.Free(); err != nil {
			t.Errorf("Free: %v", err)
		}
	}()
	if img.Base == 0 {
		t.Error("Base = 0 — mapper did not allocate")
	}
	if img.EntryPoint <= img.Base {
		t.Errorf("EntryPoint %#x not within mapped region (base %#x)",
			img.EntryPoint, img.Base)
	}
}

// TestStaticPIEGate_AcceptsNonGoSynthetic confirms Stage E
// broadens the gate so ET_DYN + no DT_NEEDED passes regardless of
// whether the binary carries .go.buildinfo. The pre-Stage-E
// contract rejected such binaries as "not a Go binary"; that gate
// is now structural-only.
//
// Pinned via CheckELFLoadable (cross-platform) so the assertion
// holds the same way operators packing on macOS / Windows would
// see when validating their Linux ELF outputs.
func TestStaticPIEGate_AcceptsNonGoSynthetic(t *testing.T) {
	elf := buildMinimalELF(t, elfHeaderOpts{Type: 3, WithDynamic: true})
	if err := runtime.CheckELFLoadable(elf); err != nil {
		t.Errorf("CheckELFLoadable(ET_DYN no DT_NEEDED, no .go.buildinfo): got %v, want nil", err)
	}
}

// TestCheckELFLoadable_RejectsETDynWithDTNeeded confirms the
// structural gate still rejects dynamically-linked ET_DYN inputs
// (the Stage E broadening only dropped the .go.buildinfo
// requirement; DT_NEEDED is still a blocker).
func TestCheckELFLoadable_RejectsETDynWithDTNeeded(t *testing.T) {
	elf := buildMinimalELF(t, elfHeaderOpts{Type: 3, WithNeeded: true})
	err := runtime.CheckELFLoadable(elf)
	if err == nil {
		t.Fatal("got nil, want non-nil error")
	}
	if !errors.Is(err, runtime.ErrNotImplemented) {
		t.Errorf("got %v, want ErrNotImplemented", err)
	}
	if !strings.Contains(err.Error(), "DT_NEEDED") {
		t.Errorf("rejection should mention DT_NEEDED; got: %v", err)
	}
}

// TestReadSelfAuxv_ContainsCanaryOverride confirms readSelfAuxv
// rewrites AT_RANDOM (type 25) to the supplied canaryPtr so the
// loaded Go runtime reads our fresh canary rather than inheriting
// the parent's stack canary.
func TestReadSelfAuxv_ContainsCanaryOverride(t *testing.T) {
	if goruntime.GOOS != "linux" {
		t.Skip("/proc/self/auxv is Linux-only")
	}
	canary := uintptr(0xCAFEBABE)
	auxv := runtime.ReadSelfAuxvForTest(canary)
	var found bool
	for _, e := range auxv {
		if e.Type == 25 { // AT_RANDOM
			if e.Val != uint64(canary) {
				t.Errorf("AT_RANDOM not overridden: got %#x, want %#x", e.Val, canary)
			}
			found = true
		}
	}
	if !found {
		t.Skip("/proc/self/auxv on this kernel doesn't carry AT_RANDOM (uncommon, no fault of ours)")
	}
}

// TestCheckELFLoadable_NotELF confirms PE / garbage inputs return
// the right sentinel.
func TestCheckELFLoadable_NotELF(t *testing.T) {
	err := runtime.CheckELFLoadable([]byte{'M', 'Z', 0, 0})
	if err == nil {
		t.Fatal("got nil, want non-nil error")
	}
	if !errors.Is(err, runtime.ErrBadELF) {
		t.Errorf("got %v, want ErrBadELF", err)
	}
	err = runtime.CheckELFLoadable(nil)
	if !errors.Is(err, runtime.ErrBadELF) {
		t.Errorf("nil input: got %v, want ErrBadELF", err)
	}
}
