//go:build amd64 && (linux || windows)

package packer

import (
	"unsafe"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
	"github.com/oioio-space/maldev/pe/packer/stubgen/stage1"
)

// hostVendorASM is the mmap'd CPUID-vendor reader, lazily allocated on
// first call to [HostCPUIDVendor]. The page is RX and persists for the
// lifetime of the process — small (one page) and cheaper to reuse than
// re-emit per call.
//
// We rely on the fact that [stage1.EmitCPUIDVendorRead]'s output is
// pure-asm with no Go-runtime dependencies, so a plain function-pointer
// call from Go works once we set up the standard funcval indirection.
// hostVendorFv keeps the heap-allocated funcval alive — the
// unsafe.Pointer cast from funcval into hostVendorFn hides the reference
// from the GC, so without an explicit typed pointer the funcval gets
// collected and subsequent calls jump into garbage. This was caught by
// TestMatchBundleHost_PicksMatchingVendor crashing on the second call
// to HostCPUIDVendor in the same process.
type cpuidFuncval struct{ code uintptr }

var (
	hostVendorFv *cpuidFuncval
	hostVendorFn func(dst unsafe.Pointer)
	// hostVendorMem retains the mmap'd RX page — without this reference
	// the slice header could be collected, leaving the funcval pointing
	// at unmapped memory.
	hostVendorMem []byte
)

// HostCPUIDVendor returns the 12-byte CPUID EAX=0 vendor string of the
// host CPU (e.g. {'G','e','n','u','i','n','e','I','n','t','e','l'}).
//
// Implemented by emitting the [stage1.EmitCPUIDVendorRead] byte sequence
// into an mmap'd RX page and invoking it via a Go function-pointer
// trampoline. No cgo, no external syscall.
//
// Returns the zero value on amd64 stub OS variants outside (linux,
// windows). The build-tag-gated [hostCPUIDVendor] callers can short-
// circuit before reaching the asm path.
//
// First call lazily emits + mmaps; subsequent calls reuse the cached
// page. Safe for concurrent calls (the page write happens once under
// the package init goroutine; concurrent readers see the finished
// pointer).
func HostCPUIDVendor() [12]byte {
	if hostVendorFn == nil {
		hostVendorFn = makeCPUIDVendorReader()
	}
	var buf [16]byte
	hostVendorFn(unsafe.Pointer(&buf[0]))
	var out [12]byte
	copy(out[:], buf[:12])
	return out
}

// MatchBundleHost is the operator-facing "would this payload fire on
// this host?" check. It reads the host's CPUID vendor (and on Windows,
// OSBuildNumber via RtlGetVersion — see bundle_host_windows.go), then
// calls [SelectPayload] against the supplied bundle.
//
// Returns -1 if no entry matches. Errors flow from [SelectPayload]
// (truncation, bad magic).
//
// On Linux the build number is reported as 0, so any entry with
// PT_WIN_BUILD + non-zero BuildMin will not match — which is the
// correct semantic since Linux bundles do not carry Windows build
// predicates.
func MatchBundleHost(bundle []byte) (int, error) {
	vendor := HostCPUIDVendor()
	build := hostWinBuild()
	return SelectPayload(bundle, vendor, build)
}

// makeCPUIDVendorReader emits EmitCPUIDVendorRead bytes into an mmap'd
// RX page, fronted by a 3-byte trampoline that loads RDI from RAX
// (Go's register ABI passes the first arg in RAX, but the asm expects
// RDI). The asm is followed by a RET so we can call it via funcval.
func makeCPUIDVendorReader() func(unsafe.Pointer) {
	b, err := amd64.New()
	if err != nil {
		panic("packer: amd64.New: " + err.Error())
	}
	if err := stage1.EmitCPUIDVendorRead(b); err != nil {
		panic("packer: EmitCPUIDVendorRead: " + err.Error())
	}
	body, err := b.Encode()
	if err != nil {
		panic("packer: Encode: " + err.Error())
	}

	// Trampoline wraps the asm so it observes the Go register ABI:
	//   - prologue: push rbx (CPUID clobbers RBX, which Go expects to be
	//     callee-saved); mov rdi, rax (Go passes first ptr arg in RAX,
	//     the asm reads dst from RDI).
	//   - epilogue: pop rbx; ret.
	prologue := []byte{0x53, 0x48, 0x89, 0xc7} // push rbx; mov rdi, rax
	epilogue := []byte{0x5b, 0xc3}             // pop rbx; ret
	full := append(append(append([]byte(nil), prologue...), body...), epilogue...)

	mem := mmapRX(len(full))
	copy(mem, full)

	hostVendorMem = mem // keep the mmap alive for the lifetime of the process
	hostVendorFv = &cpuidFuncval{code: uintptr(unsafe.Pointer(&mem[0]))}
	var fn func(unsafe.Pointer)
	*(*uintptr)(unsafe.Pointer(&fn)) = uintptr(unsafe.Pointer(hostVendorFv))
	return fn
}
