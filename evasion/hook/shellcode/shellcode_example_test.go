package shellcode_test

import (
	"fmt"

	"github.com/oioio-space/maldev/evasion/hook/shellcode"
)

// Block is `XOR RAX, RAX; RET` — the canned blob for hooks that
// need to return 0 / FALSE / NULL (e.g., AmsiScanBuffer →
// AMSI_RESULT_CLEAN, IsDebuggerPresent → false).
func ExampleBlock() {
	sc := shellcode.Block()
	fmt.Printf("block payload: %d bytes\n", len(sc))
}

// Replace returns a payload that loads an arbitrary uintptr into
// RAX and returns. Use it when the original API contract requires
// a non-zero TRUE-style return.
func ExampleReplace() {
	sc := shellcode.Replace(1) // return 1 / TRUE
	_ = sc
}

// Nop returns a trampoline-pass-through stub that jumps straight
// back to the trampoline address — used when you want hooks
// installed for telemetry but don't want to alter the function's
// behaviour.
func ExampleNop() {
	const trampolineAddr uintptr = 0x7FF8_0000_1234
	sc := shellcode.Nop(trampolineAddr)
	_ = sc
}
