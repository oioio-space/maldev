package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"reflect"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
	"github.com/oioio-space/maldev/pe/packer/stubgen/poly"
)

// runRoundDiff implements `packer-vis round-diff <file> [-rounds N] [-seed S]`.
//
// It runs the SGN polymorphic encoder over the input file's bytes,
// applies each XOR round in order, and prints a per-round table:
//
//	Round | Key (hex) | Subst    | KeyReg | ByteReg | Changed | First-16 hex preview
//
// "Changed" is the count of byte positions whose value differs from
// the previous round's output (always 100% for an 8-bit XOR with a
// non-zero key, but useful when keys collide or when later rounds
// add structure-aware substitutions).
//
// Pedagogical intent: give operators a "show me what each SGN round
// actually does to the bytes" view. Pairs with `entropy` for the
// post-encode entropy delta.
func runRoundDiff(args []string) int {
	fs := flag.NewFlagSet("round-diff", flag.ExitOnError)
	rounds := fs.Int("rounds", 4, "SGN rounds to apply (1..10)")
	seed := fs.Int64("seed", 0, "PRNG seed (0 = random)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	path := fs.Arg(0)

	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "round-diff: read %s: %v\n", path, err)
		return 1
	}

	// 0 → fresh random seed picked here so the operator can rerun and
	// see different layouts; printed in the header for reproducibility.
	if *seed == 0 {
		*seed = rand.Int63()
	}
	engine, err := poly.NewEngine(*seed, *rounds)
	if err != nil {
		fmt.Fprintf(os.Stderr, "round-diff: NewEngine(seed=%d, rounds=%d): %v\n", *seed, *rounds, err)
		return 1
	}

	// Walk the rounds in encode order so the operator sees the same
	// progression the stage-1 stub will REVERSE. Apply each round
	// step-by-step on a working copy so we can compare byte-by-byte
	// across rounds.
	_, roundDescs, err := engine.EncodePayload(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "round-diff: EncodePayload: %v\n", err)
		return 1
	}

	fmt.Printf("packer-vis round-diff — %s (%d bytes)\n", path, len(data))
	fmt.Printf("seed=%d rounds=%d\n\n", *seed, *rounds)
	fmt.Println("Round | Key  | Subst        | KeyReg | ByteReg | SrcReg | CntReg | Changed | First-16 hex")
	fmt.Println("------|------|--------------|--------|---------|--------|--------|---------|------------------------------------")

	prev := append([]byte(nil), data...)
	cur := append([]byte(nil), data...)
	for i, r := range roundDescs {
		// Apply round i to cur: cur[j] = subst.Encode(cur[j], r.Key).
		for j := range cur {
			cur[j] = r.Subst.Encode(cur[j], r.Key)
		}

		changed := 0
		for j := range cur {
			if cur[j] != prev[j] {
				changed++
			}
		}

		preview := previewHex(cur, 16)
		fmt.Printf("%5d | 0x%02X | %-13s | %-6s | %-7s | %-6s | %-6s | %7d | %s\n",
			i, r.Key, substName(r.Subst),
			regName(r.KeyReg), regName(r.ByteReg), regName(r.SrcReg), regName(r.CntReg),
			changed, preview)

		copy(prev, cur)
	}

	return 0
}

// previewHex returns the first n bytes of buf rendered as
// `aa bb cc …` (space-separated lowercase hex). Truncates with " …"
// when buf is longer than n.
func previewHex(buf []byte, n int) string {
	if len(buf) == 0 {
		return ""
	}
	if n > len(buf) {
		n = len(buf)
	}
	out := make([]byte, 0, n*3)
	for i := 0; i < n; i++ {
		if i > 0 {
			out = append(out, ' ')
		}
		out = append(out, hexNibble(buf[i]>>4), hexNibble(buf[i]&0x0F))
	}
	if len(buf) > n {
		out = append(out, ' ', 0xE2, 0x80, 0xA6) // "…"
	}
	return string(out)
}

func hexNibble(n byte) byte {
	if n < 10 {
		return '0' + n
	}
	return 'a' + (n - 10)
}

// substName identifies which entry of poly.XorSubsts produced this
// round's substitution by comparing the Encode function pointer
// against the registered table. Returns the canonical short name
// or "subst[N]" when an unrecognised pointer slips through (only
// happens if poly grows the table without updating this map).
func substName(s poly.Subst) string {
	target := reflect.ValueOf(s.Encode).Pointer()
	for i, candidate := range poly.XorSubsts {
		if reflect.ValueOf(candidate.Encode).Pointer() == target {
			return []string{"canonicalXOR", "subNegate", "addComplement"}[i%3] +
				suffixIfBeyond3(i)
		}
	}
	return "subst[?]"
}

func suffixIfBeyond3(i int) string {
	if i < 3 {
		return ""
	}
	return fmt.Sprintf("[%d]", i)
}

// regName maps an amd64.Reg constant to its canonical lowercase
// register name (rax, rbx, …). Mirrors operands.go's const block.
func regName(r amd64.Reg) string {
	switch r {
	case amd64.RAX:
		return "rax"
	case amd64.RBX:
		return "rbx"
	case amd64.RCX:
		return "rcx"
	case amd64.RDX:
		return "rdx"
	case amd64.RSI:
		return "rsi"
	case amd64.RDI:
		return "rdi"
	case amd64.R8:
		return "r8"
	case amd64.R9:
		return "r9"
	case amd64.R10:
		return "r10"
	case amd64.R11:
		return "r11"
	case amd64.R12:
		return "r12"
	case amd64.R13:
		return "r13"
	case amd64.R14:
		return "r14"
	case amd64.R15:
		return "r15"
	case amd64.RSP:
		return "rsp"
	case amd64.RBP:
		return "rbp"
	default:
		return fmt.Sprintf("reg(%d)", uint8(r))
	}
}
