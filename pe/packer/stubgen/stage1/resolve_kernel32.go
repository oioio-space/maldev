package stage1

import (
	"errors"
	"fmt"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
)

// ErrEmptyExportName fires when EmitResolveKernel32Export gets
// called with an empty exportName (hashing nothing produces hash=0
// which collides with the export-loop's index=0 starting state).
var ErrEmptyExportName = errors.New("stage1: EmitResolveKernel32Export: empty exportName")

// EmitResolveKernel32Export writes asm that resolves the absolute
// VA of `kernel32!<exportName>` at runtime via a PEB walk +
// export-name-table hash match. The resolved VA lands in R13.
//
// Register contract:
//   - Inputs:  none (uses gs:[0x60])
//   - Output:  R13 = absolute VA of kernel32!<exportName>
//   - Clobbers: RAX, RBX, RCX, RDX, R8, R9, R10, R11, R12
//   - Preserves: R13 (only assigned at the end), R14, R15
//
// Slice 5.2 of docs/refactor-2026-doc/packer-exe-to-dll-plan.md.
// The converted-EXE-as-DLL stub (slice 5.3) calls this after the
// CALL+POP+ADD prologue so R15 still holds the runtime textBase.
//
// Hashing: Stephen-Fewer-style ROR-13 (XOR variant). Module name
// is the Unicode BaseDllName from LDR_DATA_TABLE_ENTRY, folded to
// uppercase before each XOR (case-insensitive — matches Windows
// loader behaviour). Export names are NUL-terminated ASCII, hashed
// byte-by-byte without folding (Windows export names are
// case-sensitive).
//
// The asm assumes kernel32.dll is loaded into the process — true
// on every Windows user-mode binary since the OS forces it into
// the initial loader set. If kernel32 is somehow absent the
// module_loop spins forever (consistent with reflective-DLL-
// injection shellcode standard practice).
//
// If the exportName is not found in kernel32's EAT, R13 is left
// unchanged and execution falls through. Callers MUST seed R13 to
// a known-bad value beforehand if they want to detect this case.
func EmitResolveKernel32Export(b *amd64.Builder, exportName string) error {
	if exportName == "" {
		return ErrEmptyExportName
	}
	exportHash := Ror13HashASCII(exportName)

	// === Phase 1: PEB → Ldr → InMemoryOrderList.Flink in R12 ===
	//
	// LDR_DATA_TABLE_ENTRY layout (Win10+, x64). R12 will track
	// InMemoryOrderLinks, which is at +0x10 inside the entry.
	// All subsequent reads compensate by subtracting 0x10:
	//   DllBase           [r12 + 0x20]   (entry+0x30)
	//   BaseDllName.Length [r12 + 0x48]  (entry+0x58, USHORT)
	//   BaseDllName.Buffer [r12 + 0x50]  (entry+0x60, PWSTR)
	if err := b.RawBytes([]byte{
		// mov rax, gs:[0x60]              ; PEB
		0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,
		// mov rax, [rax + 0x18]           ; PEB.Ldr (PEB_LDR_DATA*)
		0x48, 0x8B, 0x40, 0x18,
		// mov r12, [rax + 0x20]           ; InMemoryOrderModuleList.Flink
		0x4C, 0x8B, 0x60, 0x20,
	}); err != nil {
		return fmt.Errorf("stage1: emit PEB walk: %w", err)
	}

	// === Phase 2: module loop — find kernel32.dll by BaseDllName hash ===
	moduleLoopLbl := b.Label("k32_module_loop")
	// movzx ecx, word ptr [r12 + 0x48]    ; BaseDllName.Length (bytes)
	if err := b.MOVZWL(amd64.RCX, amd64.MemOp{Base: amd64.R12, Disp: 0x48}); err != nil {
		return fmt.Errorf("stage1: emit movzwl BaseDllName.Length: %w", err)
	}
	// mov r8, [r12 + 0x50]                ; BaseDllName.Buffer
	if err := b.MOV(amd64.R8, amd64.MemOp{Base: amd64.R12, Disp: 0x50}); err != nil {
		return fmt.Errorf("stage1: emit mov R8, BaseDllName.Buffer: %w", err)
	}
	// shr ecx, 1                          ; bytes → chars
	if err := b.RawBytes([]byte{0xD1, 0xE9}); err != nil {
		return fmt.Errorf("stage1: emit shr ecx: %w", err)
	}
	// xor r10d, r10d                      ; hash = 0
	if err := b.XOR(amd64.R10, amd64.R10); err != nil {
		return fmt.Errorf("stage1: emit xor r10d: %w", err)
	}

	// Module hash loop: per-wchar fold-and-hash.
	moduleHashLbl := b.Label("k32_module_hash")
	// test ecx, ecx ; jz module_hash_done
	if err := b.TEST(amd64.RCX, amd64.RCX); err != nil {
		return fmt.Errorf("stage1: emit test rcx: %w", err)
	}
	if err := b.JE(amd64.LabelRef("k32_module_hash_done")); err != nil {
		return fmt.Errorf("stage1: emit je module_hash_done: %w", err)
	}
	// movzx eax, word ptr [r8]
	if err := b.MOVZWL(amd64.RAX, amd64.MemOp{Base: amd64.R8}); err != nil {
		return fmt.Errorf("stage1: emit movzwl wchar: %w", err)
	}
	// Case fold: if [a..z], subtract 0x20. JB/JA aren't exposed by
	// Builder; the fold block has a fixed size so we hand-code the
	// two short forward jumps with computed displacements.
	if err := b.RawBytes([]byte{
		// cmp eax, 0x61 ('a')
		0x83, 0xF8, 0x61,
		// jb +8 → skip cmp/ja/sub (8 bytes follow before fold_skip)
		0x72, 0x08,
		// cmp eax, 0x7A ('z')
		0x83, 0xF8, 0x7A,
		// ja +3 → skip sub
		0x77, 0x03,
		// sub eax, 0x20 (fold to upper)
		0x83, 0xE8, 0x20,
		// fold_skip: (implicit position)
		// ror r10d, 13
		0x41, 0xC1, 0xCA, 0x0D,
	}); err != nil {
		return fmt.Errorf("stage1: emit fold + ror: %w", err)
	}
	// xor r10d, eax
	if err := b.XOR(amd64.R10, amd64.RAX); err != nil {
		return fmt.Errorf("stage1: emit xor r10d, eax: %w", err)
	}
	// add r8, 2
	if err := b.ADD(amd64.R8, amd64.Imm(2)); err != nil {
		return fmt.Errorf("stage1: emit add r8,2: %w", err)
	}
	// dec ecx — Builder's DEC is 64-bit; use RawBytes for ECX form.
	if err := b.RawBytes([]byte{0xFF, 0xC9}); err != nil {
		return fmt.Errorf("stage1: emit dec ecx: %w", err)
	}
	// jmp module_hash (backward)
	if err := b.JMP(moduleHashLbl); err != nil {
		return fmt.Errorf("stage1: emit jmp module_hash: %w", err)
	}

	// module_hash_done: compare against Kernel32DLLHash; if match,
	// continue to EAT walk. Otherwise advance Flink and loop.
	_ = b.Label("k32_module_hash_done")
	// cmp r10d, Kernel32DLLHash
	if err := b.CMPL(amd64.R10, amd64.Imm(int64(Kernel32DLLHash))); err != nil {
		return fmt.Errorf("stage1: emit cmp r10d, Kernel32DLLHash: %w", err)
	}
	if err := b.JE(amd64.LabelRef("k32_module_found")); err != nil {
		return fmt.Errorf("stage1: emit je module_found: %w", err)
	}
	// mov r12, [r12]              ; Flink → next entry's InMemoryOrderLinks
	if err := b.MOV(amd64.R12, amd64.MemOp{Base: amd64.R12}); err != nil {
		return fmt.Errorf("stage1: emit mov r12, [r12]: %w", err)
	}
	if err := b.JMP(moduleLoopLbl); err != nil {
		return fmt.Errorf("stage1: emit jmp k32_module_loop: %w", err)
	}

	// === Phase 3: kernel32 base in R12, walk EAT ===
	_ = b.Label("k32_module_found")
	// mov r12, [r12 + 0x20]        ; DllBase (LDR entry+0x30; r12 base = entry+0x10)
	if err := b.MOV(amd64.R12, amd64.MemOp{Base: amd64.R12, Disp: 0x20}); err != nil {
		return fmt.Errorf("stage1: emit mov r12, DllBase: %w", err)
	}
	// mov eax, [r12 + 0x3C]        ; e_lfanew
	if err := b.MOVL(amd64.RAX, amd64.MemOp{Base: amd64.R12, Disp: 0x3C}); err != nil {
		return fmt.Errorf("stage1: emit movl eax, e_lfanew: %w", err)
	}
	// mov ebx, [r12 + rax + 0x88]  ; ExportDir RVA (DataDirectory[0].VA for PE32+)
	if err := b.MOVL(amd64.RBX, amd64.MemOp{Base: amd64.R12, Index: amd64.RAX, Scale: 1, Disp: 0x88}); err != nil {
		return fmt.Errorf("stage1: emit movl ebx, ExportDir RVA: %w", err)
	}
	// add rbx, r12                  ; ExportDir VA
	if err := b.ADD(amd64.RBX, amd64.R12); err != nil {
		return fmt.Errorf("stage1: emit add rbx, r12: %w", err)
	}
	// mov ecx, [rbx + 0x18]        ; NumberOfNames
	if err := b.MOVL(amd64.RCX, amd64.MemOp{Base: amd64.RBX, Disp: 0x18}); err != nil {
		return fmt.Errorf("stage1: emit movl ecx, NumberOfNames: %w", err)
	}
	// mov r8d, [rbx + 0x20]        ; AddressOfNames RVA
	if err := b.MOVL(amd64.R8, amd64.MemOp{Base: amd64.RBX, Disp: 0x20}); err != nil {
		return fmt.Errorf("stage1: emit movl r8d, AddressOfNames RVA: %w", err)
	}
	// add r8, r12                   ; AddressOfNames VA (DWORD[])
	if err := b.ADD(amd64.R8, amd64.R12); err != nil {
		return fmt.Errorf("stage1: emit add r8, r12: %w", err)
	}
	// xor r11d, r11d                ; name index
	if err := b.XOR(amd64.R11, amd64.R11); err != nil {
		return fmt.Errorf("stage1: emit xor r11d: %w", err)
	}

	// === Phase 4: export loop — match name hash ===
	exportLoopLbl := b.Label("k32_export_loop")
	// mov eax, [r8 + r11*4]         ; name RVA at index r11
	if err := b.MOVL(amd64.RAX, amd64.MemOp{Base: amd64.R8, Index: amd64.R11, Scale: 4}); err != nil {
		return fmt.Errorf("stage1: emit movl name RVA: %w", err)
	}
	// add rax, r12                  ; name VA (NUL-terminated ASCII)
	if err := b.ADD(amd64.RAX, amd64.R12); err != nil {
		return fmt.Errorf("stage1: emit add rax, r12: %w", err)
	}
	// xor r10d, r10d                ; hash = 0
	if err := b.XOR(amd64.R10, amd64.R10); err != nil {
		return fmt.Errorf("stage1: emit xor r10d (export hash): %w", err)
	}
	// export hash loop
	exportHashLbl := b.Label("k32_export_hash")
	// movzx edx, byte ptr [rax]
	if err := b.MOVZX(amd64.RDX, amd64.MemOp{Base: amd64.RAX}); err != nil {
		return fmt.Errorf("stage1: emit movzx edx, byte: %w", err)
	}
	// test edx, edx ; jz export_hash_done
	if err := b.TEST(amd64.RDX, amd64.RDX); err != nil {
		return fmt.Errorf("stage1: emit test edx: %w", err)
	}
	if err := b.JE(amd64.LabelRef("k32_export_hash_done")); err != nil {
		return fmt.Errorf("stage1: emit je export_hash_done: %w", err)
	}
	// ror r10d, 13 ; xor r10d, edx ; inc rax ; jmp hash_loop
	if err := b.RawBytes([]byte{0x41, 0xC1, 0xCA, 0x0D}); err != nil { // ror r10d, 13
		return fmt.Errorf("stage1: emit ror r10d (export): %w", err)
	}
	if err := b.XOR(amd64.R10, amd64.RDX); err != nil {
		return fmt.Errorf("stage1: emit xor r10d, edx: %w", err)
	}
	if err := b.RawBytes([]byte{0x48, 0xFF, 0xC0}); err != nil { // inc rax
		return fmt.Errorf("stage1: emit inc rax: %w", err)
	}
	if err := b.JMP(exportHashLbl); err != nil {
		return fmt.Errorf("stage1: emit jmp export_hash: %w", err)
	}

	// export_hash_done: compare against the spliced exportHash.
	_ = b.Label("k32_export_hash_done")
	if err := b.CMPL(amd64.R10, amd64.Imm(int64(exportHash))); err != nil {
		return fmt.Errorf("stage1: emit cmp r10d, exportHash: %w", err)
	}
	if err := b.JE(amd64.LabelRef("k32_export_found")); err != nil {
		return fmt.Errorf("stage1: emit je export_found: %w", err)
	}
	// inc r11d ; dec ecx ; jnz export_loop ; (else fall through — not found)
	if err := b.RawBytes([]byte{0x41, 0xFF, 0xC3}); err != nil { // inc r11d
		return fmt.Errorf("stage1: emit inc r11d: %w", err)
	}
	if err := b.RawBytes([]byte{0xFF, 0xC9}); err != nil { // dec ecx
		return fmt.Errorf("stage1: emit dec ecx (export loop): %w", err)
	}
	if err := b.JNZ(exportLoopLbl); err != nil {
		return fmt.Errorf("stage1: emit jnz export_loop: %w", err)
	}
	if err := b.JMP(amd64.LabelRef("k32_resolve_done")); err != nil {
		return fmt.Errorf("stage1: emit jmp resolve_done (not found): %w", err)
	}

	// === Phase 5: export found — translate ordinal → function VA ===
	_ = b.Label("k32_export_found")
	// mov r9d, [rbx + 0x24]         ; AddressOfNameOrdinals RVA
	if err := b.MOVL(amd64.R9, amd64.MemOp{Base: amd64.RBX, Disp: 0x24}); err != nil {
		return fmt.Errorf("stage1: emit movl r9d, AddressOfNameOrdinals RVA: %w", err)
	}
	// add r9, r12                    ; ordinals VA (WORD[])
	if err := b.ADD(amd64.R9, amd64.R12); err != nil {
		return fmt.Errorf("stage1: emit add r9, r12: %w", err)
	}
	// movzx r9d, word ptr [r9 + r11*2]
	if err := b.MOVZWL(amd64.R9, amd64.MemOp{Base: amd64.R9, Index: amd64.R11, Scale: 2}); err != nil {
		return fmt.Errorf("stage1: emit movzwl r9d, ordinal: %w", err)
	}
	// mov eax, [rbx + 0x1C]         ; AddressOfFunctions RVA
	if err := b.MOVL(amd64.RAX, amd64.MemOp{Base: amd64.RBX, Disp: 0x1C}); err != nil {
		return fmt.Errorf("stage1: emit movl eax, AddressOfFunctions RVA: %w", err)
	}
	// add rax, r12                  ; AddressOfFunctions VA (DWORD[])
	if err := b.ADD(amd64.RAX, amd64.R12); err != nil {
		return fmt.Errorf("stage1: emit add rax, r12 (functions): %w", err)
	}
	// mov eax, [rax + r9*4]         ; function RVA
	if err := b.MOVL(amd64.RAX, amd64.MemOp{Base: amd64.RAX, Index: amd64.R9, Scale: 4}); err != nil {
		return fmt.Errorf("stage1: emit movl eax, function RVA: %w", err)
	}
	// add rax, r12                  ; function absolute VA
	if err := b.ADD(amd64.RAX, amd64.R12); err != nil {
		return fmt.Errorf("stage1: emit add rax, r12 (function): %w", err)
	}
	// mov r13, rax
	if err := b.MOV(amd64.R13, amd64.RAX); err != nil {
		return fmt.Errorf("stage1: emit mov r13, rax: %w", err)
	}

	_ = b.Label("k32_resolve_done")
	return nil
}
