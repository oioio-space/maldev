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
// Encoding (12 bytes):
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

// GSLoadPEBBytes encodes the 9-byte `mov rax, gs:[0x60]` instruction —
// loading the Process Environment Block pointer through the GS segment
// register (x64 NT convention). Every stub that walks the PEB starts
// with this same sequence; deduplicated here so emitters reference one
// canonical encoding instead of pasting magic bytes in 5 places.
//
//	mov rax, gs:[0x60]   ; 65 48 8b 04 25 60 00 00 00
var GSLoadPEBBytes = [9]byte{0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00}

// pebBuildBytes reads the Windows OSBuildNumber (DWORD at PEB+0x120) and
// returns it in EAX.
//
// Encoding (15 bytes):
//
//	mov rax, gs:[0x60]      ; 65 48 8b 04 25 60 00 00 00   (GSLoadPEBBytes)
//	mov eax, [rax + 0x120]  ; 8b 80 20 01 00 00
//
// PEB offsets (Win10+, x64) confirmed against ReactOS + WinDbg dumps:
//
//	0x118 OSMajorVersion    (DWORD)
//	0x11C OSMinorVersion    (DWORD)
//	0x120 OSBuildNumber     (DWORD)
var pebBuildBytes = append(append([]byte(nil), GSLoadPEBBytes[:]...),
	0x8b, 0x80, 0x20, 0x01, 0x00, 0x00, // mov eax, [rax+0x120]
)

// EmitCPUIDVendorRead appends the 12-byte CPUID-vendor reader to b.
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

// vendorCompareBytes compares the 12-byte vendor string at [RDI] against
// [RSI], setting ZF=1 if all 12 bytes match. Caller-provided pointers
// must be readable for 12 bytes each.
//
// The compare is a fused 8-byte qword cmp + 4-byte dword cmp. Both
// comparisons must succeed (sequential CMP — second only runs if first
// passes via JNE). On mismatch ZF=0 and execution falls through to the
// caller; on match ZF=1.
//
// Encoding (16 bytes):
//
//	mov   r10, [rdi]            ; 4c 8b 17        — load entry-vendor low qword
//	cmp   r10, [rsi]            ; 4c 3b 16        — vs host
//	jne   skip                  ; 75 06           — short forward jmp on mismatch
//	mov   r10d, [rdi+8]         ; 44 8b 57 08     — load entry-vendor high dword
//	cmp   r10d, [rsi+8]         ; 44 3b 56 08     — vs host
//	skip:                       ; (fall-through; ZF reflects last cmp)
//
// On the JNE path ZF stays 0 (the earlier qword cmp set it). On the
// fall-through ZF reflects the dword cmp. Either way ZF==1 ⇔ all 12
// bytes equal.
//
// Clobbers: R10. Caller-saved per Go ABI; no save needed.
var vendorCompareBytes = [...]byte{
	0x4c, 0x8b, 0x17, // mov r10, [rdi]
	0x4c, 0x3b, 0x16, // cmp r10, [rsi]
	0x75, 0x06, //       jne +6 → skip
	0x44, 0x8b, 0x57, 0x08, // mov r10d, [rdi+8]
	0x44, 0x3b, 0x56, 0x08, // cmp r10d, [rsi+8]
	// skip: (next instruction emitted by caller observes ZF)
}

// EmitVendorCompare appends the 16-byte 12-byte-vendor-compare sequence
// to b. After the bytes execute, ZF=1 iff [RDI..RDI+12) == [RSI..RSI+12).
//
// Register contract:
//   - Input:  RDI, RSI = 12-byte buffers
//   - Output: ZF = match flag (use JE / JNE / SETZ to consume)
//   - Clobbers: R10
//
// Caller chains a Jcc immediately after to branch on the outcome.
//
// Tested via [TestEmitVendorCompare_RuntimeMatchesAndMisses] which
// emits the bytes into an mmap'd RX page, calls them on equal +
// unequal vendor pairs, and asserts the ZF outcome via the SETZ AL
// post-amble appended by the test harness.
func EmitVendorCompare(b *amd64.Builder) error {
	if err := b.RawBytes(vendorCompareBytes[:]); err != nil {
		return fmt.Errorf("stage1: EmitVendorCompare: %w", err)
	}
	return nil
}

// buildRangeBytes is the 34-byte encoding for [EmitBuildRangeCheck].
// Computes:
//
//	AL = ((BuildMin == 0) || (host >= BuildMin))
//	     && ((BuildMax == 0) || (host <= BuildMax))
//
// Wire-format references (per spec §3.3):
//
//	[RDI + 16] = BuildMin (DWORD, little-endian; 0 = no lower bound)
//	[RDI + 20] = BuildMax (DWORD, little-endian; 0 = no upper bound)
//
// Layout:
//  1. AL = 1 (default pass).
//  2. Load BuildMin → R10. If non-zero and host < min, AL = 0.
//  3. Load BuildMax → R10. If non-zero and host > max, AL = 0.
//
// `cmp r10d, eax` followed by `jbe +N` jumps when r10d <= eax (i.e.
// BuildMin <= host → in range). `jae +N` after the second cmp jumps
// when r10d >= eax (BuildMax >= host → in range). Both branches skip
// the AL=0 reset; falls through with AL unchanged.
var buildRangeBytes = [...]byte{
	0xb0, 0x01, //             mov al, 1                  (default pass)
	0x44, 0x8b, 0x57, 0x10, // mov r10d, [rdi+16]         BuildMin
	0x45, 0x85, 0xd2, //       test r10d, r10d
	0x74, 0x06, //             je +6 → skip_min
	0x41, 0x39, 0xc2, //       cmp r10d, eax              (min vs host)
	0x76, 0x02, //             jbe +2 → skip_min          (min <= host → ok)
	0xb0, 0x00, //             mov al, 0                  (host < min → fail)
	// skip_min:
	0x44, 0x8b, 0x57, 0x14, // mov r10d, [rdi+20]         BuildMax
	0x45, 0x85, 0xd2, //       test r10d, r10d
	0x74, 0x06, //             je +6 → done
	0x41, 0x39, 0xc2, //       cmp r10d, eax              (max vs host)
	0x73, 0x02, //             jae +2 → done              (max >= host → ok)
	0xb0, 0x00, //             mov al, 0                  (host > max → fail)
	// done:
}

// EmitBuildRangeCheck appends the 34-byte build-range check to b. The
// emitted asm reads BuildMin from `[RDI + 16]` and BuildMax from
// `[RDI + 20]`, both DWORDs, and compares them against EAX (the host
// build number).
//
// Result: AL = 1 on pass (in range or unbounded), 0 on fail. The
// caller composes this with [EmitVendorCompare] by ANDing the two
// result flags, or branches via TEST AL,AL + Jcc.
//
// Register contract:
//   - Input:  RDI = FingerprintEntry pointer, EAX = host build
//   - Output: AL = 1 if the host build matches the entry range
//   - Clobbers: R10, AL (caller-saved per Go ABI)
//
// Encoding pinned via [TestEmitBuildRangeCheck_BytesShape]; runtime
// exercise via the bundle E2E (a packed binary running standalone, no
// Go test harness).
func EmitBuildRangeCheck(b *amd64.Builder) error {
	if err := b.RawBytes(buildRangeBytes[:]); err != nil {
		return fmt.Errorf("stage1: EmitBuildRangeCheck: %w", err)
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
