package stage1

import (
	"fmt"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
	"github.com/oioio-space/maldev/pe/packer/transform"
)

// emitAntiDebugWindowsPE appends a ~70-byte anti-debug prologue to b.
//
// Three checks run in order; a positive result on any one jumps to an
// inline RET. The RET is clean because ntdll!RtlUserThreadStart's epilogue
// calls ExitProcess(0) — the process exits with code 0 and no SGN-side
// artefacts are revealed in memory.
//
// Check 1 — PEB.BeingDebugged
//
//	TEB lives at gs:[0x60] on x64 (winnt.h PEB_OFFSET). Byte at PEB+2 is
//	the BeingDebugged flag; non-zero means a kernel debugger is attached.
//
// Check 2 — PEB.NtGlobalFlag
//
//	DWORD at PEB+0xBC carries NtGlobalFlag. A debugger (and some sandbox
//	emulators) sets the heap-validation triad (0x70):
//	  FLG_HEAP_ENABLE_TAIL_CHECK      (0x10)
//	  FLG_HEAP_ENABLE_FREE_CHECK      (0x20)
//	  FLG_HEAP_VALIDATE_PARAMETERS    (0x40)
//
// Check 3 — RDTSC delta around CPUID
//
//	Intel SDM Vol. 2B, RDTSC entry: the instruction is not serializing, but
//	CPUID forces a pipeline flush and, under HVM, a VMEXIT. A debugger that
//	hooks the dispatch path inflates the VMEXIT latency well above 1000
//	cycles. We bracket a CPUID (leaf 0) with two RDTSC reads; a delta above
//	the threshold means an observer is present.
//
// All GS-prefixed loads are emitted via RawBytes because golang-asm's Plan 9
// surface does not expose a GS segment-register override. The encodings are
// fixed by Intel SDM Vol. 2A, MOV r64, mem with segment prefix 0x65.
func emitAntiDebugWindowsPE(b *amd64.Builder) error {
	// All three branches forward-jump to a single RET at the end of the
	// prologue. golang-asm resolves forward LabelRefs in its two-pass
	// Assemble; we anchor the label after the last check below.
	const exitLabel = "antidebug_exit_clean"

	// Check 1: PEB.BeingDebugged ─────────────────────────────────────────
	// mov rax, gs:[0x60]
	if err := b.RawBytes(GSLoadPEBBytes[:]); err != nil {
		return fmt.Errorf("stage1: antidebug BeingDebugged gs load: %w", err)
	}
	// movzx eax, byte ptr [rax+2]
	if err := b.RawBytes([]byte{0x0F, 0xB6, 0x40, 0x02}); err != nil {
		return fmt.Errorf("stage1: antidebug BeingDebugged movzx: %w", err)
	}
	// test al, al
	if err := b.RawBytes([]byte{0x84, 0xC0}); err != nil {
		return fmt.Errorf("stage1: antidebug BeingDebugged test: %w", err)
	}
	if err := b.JNZ(amd64.LabelRef(exitLabel)); err != nil {
		return fmt.Errorf("stage1: antidebug BeingDebugged jnz: %w", err)
	}

	// Check 2: PEB.NtGlobalFlag ──────────────────────────────────────────
	// mov rax, gs:[0x60]
	if err := b.RawBytes(GSLoadPEBBytes[:]); err != nil {
		return fmt.Errorf("stage1: antidebug NtGlobalFlag gs load: %w", err)
	}
	// mov eax, [rax+0xBC]
	if err := b.RawBytes([]byte{0x8B, 0x80, 0xBC, 0x00, 0x00, 0x00}); err != nil {
		return fmt.Errorf("stage1: antidebug NtGlobalFlag load: %w", err)
	}
	// and eax, 0x70
	if err := b.RawBytes([]byte{0x25, 0x70, 0x00, 0x00, 0x00}); err != nil {
		return fmt.Errorf("stage1: antidebug NtGlobalFlag and: %w", err)
	}
	if err := b.JNZ(amd64.LabelRef(exitLabel)); err != nil {
		return fmt.Errorf("stage1: antidebug NtGlobalFlag jnz: %w", err)
	}

	// Check 3: RDTSC delta around CPUID ──────────────────────────────────
	// rdtsc — EDX:EAX = TSC before CPUID
	if err := b.RawBytes([]byte{0x0F, 0x31}); err != nil {
		return fmt.Errorf("stage1: antidebug rdtsc1: %w", err)
	}
	// shl rdx, 32
	if err := b.RawBytes([]byte{0x48, 0xC1, 0xE2, 0x20}); err != nil {
		return fmt.Errorf("stage1: antidebug shl rdx: %w", err)
	}
	// or rax, rdx — rax = full 64-bit TSC
	if err := b.RawBytes([]byte{0x48, 0x09, 0xD0}); err != nil {
		return fmt.Errorf("stage1: antidebug or rax rdx: %w", err)
	}
	// mov r10, rax — save TSC₀; r10 is caller-saved (Windows x64 ABI §4.3.1)
	if err := b.RawBytes([]byte{0x49, 0x89, 0xC2}); err != nil {
		return fmt.Errorf("stage1: antidebug mov r10: %w", err)
	}
	// xor eax, eax — CPUID leaf 0
	if err := b.RawBytes([]byte{0x31, 0xC0}); err != nil {
		return fmt.Errorf("stage1: antidebug xor eax: %w", err)
	}
	// cpuid — serialize + potential VMEXIT under HVM
	if err := b.RawBytes([]byte{0x0F, 0xA2}); err != nil {
		return fmt.Errorf("stage1: antidebug cpuid: %w", err)
	}
	// rdtsc — TSC after CPUID
	if err := b.RawBytes([]byte{0x0F, 0x31}); err != nil {
		return fmt.Errorf("stage1: antidebug rdtsc2: %w", err)
	}
	// shl rdx, 32
	if err := b.RawBytes([]byte{0x48, 0xC1, 0xE2, 0x20}); err != nil {
		return fmt.Errorf("stage1: antidebug shl rdx2: %w", err)
	}
	// or rax, rdx — rax = full 64-bit TSC₁
	if err := b.RawBytes([]byte{0x48, 0x09, 0xD0}); err != nil {
		return fmt.Errorf("stage1: antidebug or rax rdx2: %w", err)
	}
	// sub rax, r10 — delta = TSC₁ − TSC₀
	// REX.W=1 REX.R=1 (r10) → 0x4C; SUB r/m64,r64 = 0x29;
	// ModRM mod=11 reg=r10(010) rm=rax(000) → 0xD0.
	if err := b.RawBytes([]byte{0x4C, 0x29, 0xD0}); err != nil {
		return fmt.Errorf("stage1: antidebug sub: %w", err)
	}
	// cmp rax, 1000 — threshold tuned against Win10/Win11 baseline
	// (unmonitored CPUID latency ~200–400 cycles). Sandboxed/throttled
	// deployments may false-positive; leave AntiDebug off in those cases.
	if err := b.RawBytes([]byte{0x48, 0x3D, 0xE8, 0x03, 0x00, 0x00}); err != nil {
		return fmt.Errorf("stage1: antidebug cmp 1000: %w", err)
	}
	// JA exit_clean: encoded as JBE-over-JMP because Builder exposes only
	// JNZ/JE. golang-asm always resolves a LabelRef JMP to a 5-byte E9
	// near jump, so JBE displacement = 5 skips it cleanly.
	// JBE +5 — NOT above → fall through to SGN decoder
	if err := b.RawBytes([]byte{0x76, 0x05}); err != nil {
		return fmt.Errorf("stage1: antidebug rdtsc jbe: %w", err)
	}
	// JMP exit_clean
	if err := b.JMP(amd64.LabelRef(exitLabel)); err != nil {
		return fmt.Errorf("stage1: antidebug rdtsc jmp: %w", err)
	}

	// exit_clean ─────────────────────────────────────────────────────────
	// Anchor the label; all three Jcc branches resolve here.
	// R15 has not been written yet (CALL+POP+ADD prologue follows), so the
	// RET exits with whatever R15 the caller had. Windows x64 designates
	// R15 callee-saved (§4.3.1), so our caller preserves it across calls.
	_ = b.Label(exitLabel)
	if err := b.RET(); err != nil {
		return fmt.Errorf("stage1: antidebug RET: %w", err)
	}

	return nil
}

// emitAntiDebug prepends the Windows PE anti-debug prologue to b, or does
// nothing for ELF. Linux ptrace detection requires signal-handler plumbing
// (SIGTRAP / ptrace(PTRACE_TRACEME)) that does not fit the stub size budget.
func emitAntiDebug(b *amd64.Builder, format transform.Format) error {
	if format == transform.FormatPE {
		return emitAntiDebugWindowsPE(b)
	}
	return nil
}
