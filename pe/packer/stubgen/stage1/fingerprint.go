package stage1

import (
	"fmt"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
)

// Fingerprint asm emitters for the C6 multi-target bundle stub.
//
// These emit raw byte sequences that the bundle stub uses to read the
// host's CPUID vendor string and Windows OSBuildNumber WITHOUT calling
// any OS API or library. The values feed FingerprintPredicate evaluation.
//
// See docs/superpowers/specs/2026-05-08-packer-multi-target-bundle.md §10
// for the spec and the byte-level reference.

// cpuidVendorBytes reads the CPUID EAX=0 vendor string and stores it as
// 12 contiguous bytes at [RDI]. Caller passes the destination pointer
// in RDI and gets all 12 bytes written.
//
// Encoding (15 bytes):
//
//	xor eax, eax            ; 31 c0
//	cpuid                   ; 0f a2
//	mov [rdi+0], ebx        ; 89 1f
//	mov [rdi+4], edx        ; 89 57 04
//	mov [rdi+8], ecx        ; 89 4f 08
//
// Note the EBX→EDX→ECX order (Intel SDM Vol. 2A): vendor bytes 0–3 = EBX,
// 4–7 = EDX, 8–11 = ECX. EAX returns clobbered (max input value); RBX is
// caller-saved per Go ABI here.
var cpuidVendorBytes = [...]byte{
	0x31, 0xc0, // xor eax, eax
	0x0f, 0xa2, // cpuid
	0x89, 0x1f, // mov [rdi], ebx        — bytes 0–3
	0x89, 0x57, 0x04, // mov [rdi+4], edx — bytes 4–7
	0x89, 0x4f, 0x08, // mov [rdi+8], ecx — bytes 8–11
}

// pebBuildBytes reads the Windows OSBuildNumber (DWORD at PEB+0x120) and
// returns it in EAX. The PEB is fetched from the GS segment register at
// offset 0x60 (x64 NT convention).
//
// Encoding (10 bytes):
//
//	mov rax, gs:[0x60]      ; 65 48 8b 04 25 60 00 00 00
//	mov eax, [rax + 0x120]  ; 8b 80 20 01 00 00
//
// Wait: gs-relative MOV with absolute disp encodes longer; using
// gs:[disp32] is the standard form. Final encoding is 16 bytes (see
// EmitPEBBuildRead doc).
//
// PEB offsets (Win10+, x64) confirmed against ReactOS + WinDbg dumps:
//
//	0x118 OSMajorVersion    (DWORD)
//	0x11C OSMinorVersion    (DWORD)
//	0x120 OSBuildNumber     (DWORD)
var pebBuildBytes = [...]byte{
	0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, // mov rax, gs:[0x60]
	0x8b, 0x80, 0x20, 0x01, 0x00, 0x00, // mov eax, [rax+0x120]
}

// EmitCPUIDVendorRead appends the 13-byte CPUID-vendor reader to b.
//
// Register contract:
//   - Input:  RDI = 12-byte destination buffer (writable)
//   - Output: [RDI..RDI+12) = vendor bytes (e.g. "GenuineIntel")
//   - Clobbers: RAX, RBX, RCX, RDX (caller-saved per Go ABI)
//
// The decoder runs to completion; no return / branch. Caller is expected
// to follow it with predicate-comparison code emitted by the bundle
// evaluator.
//
// Tested via [TestEmitCPUIDVendorRead] which mmaps the bytes as RX and
// invokes them on a 12-byte buffer, asserting the output matches what
// `golang.org/x/sys/cpu` reports for the same host.
func EmitCPUIDVendorRead(b *amd64.Builder) error {
	if err := b.RawBytes(cpuidVendorBytes[:]); err != nil {
		return fmt.Errorf("stage1: EmitCPUIDVendorRead: %w", err)
	}
	return nil
}

// EmitPEBBuildRead appends the 15-byte PEB-OSBuildNumber reader to b.
//
// Register contract:
//   - Input:  none
//   - Output: EAX = OSBuildNumber (e.g. 22631 for Win11 23H2)
//   - Clobbers: RAX (caller-saved)
//
// Windows-only — the GS segment carries the PEB on Windows x64 only.
// Linux x64 uses GS for thread-local storage with completely different
// semantics; calling this on Linux faults or returns garbage. The
// bundle stub guards by checking the host OS via the binary's container
// (PE → Windows; ELF → Linux) before emitting this code path.
//
// Tested via [TestEmitPEBBuildRead_BytesShape] (encoding-only — runtime
// behaviour requires a Windows VM and is exercised by the bundle E2E).
func EmitPEBBuildRead(b *amd64.Builder) error {
	if err := b.RawBytes(pebBuildBytes[:]); err != nil {
		return fmt.Errorf("stage1: EmitPEBBuildRead: %w", err)
	}
	return nil
}
