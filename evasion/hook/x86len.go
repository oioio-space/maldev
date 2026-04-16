package hook

import (
	"fmt"

	"golang.org/x/arch/x86/x86asm"
)

type ripReloc struct {
	instrOffset int
	dispOffset  int
	instrLen    int
	origDisp    int32
}

// analyzePrologue decodes instructions from prologue until the cumulative
// length reaches at least minBytes, and detects RIP-relative operands in
// the stolen region. Single pass — avoids decoding the same bytes twice.
func analyzePrologue(prologue []byte, minBytes int) (stealLen int, relocs []ripReloc, err error) {
	offset := 0
	for offset < minBytes {
		if offset >= len(prologue) {
			return 0, nil, fmt.Errorf("prologue too short: decoded %d bytes, need %d", offset, minBytes)
		}
		inst, decErr := x86asm.Decode(prologue[offset:], 64)
		if decErr != nil {
			return 0, nil, fmt.Errorf("decode at offset %d: %w", offset, decErr)
		}

		for _, arg := range inst.Args {
			switch a := arg.(type) {
			case x86asm.Mem:
				if a.Base != x86asm.RIP {
					continue
				}
				dOff, found := findRelOffset(prologue[offset:offset+inst.Len], a.Disp)
				if !found {
					return 0, nil, fmt.Errorf("RIP-relative disp not found at offset %d", offset)
				}
				relocs = append(relocs, ripReloc{
					instrOffset: offset,
					dispOffset:  dOff,
					instrLen:    inst.Len,
					origDisp:    int32(a.Disp),
				})
			case x86asm.Rel:
				dOff, found := findRelOffset(prologue[offset:offset+inst.Len], int64(a))
				if !found {
					return 0, nil, fmt.Errorf("relative disp not found at offset %d", offset)
				}
				relocs = append(relocs, ripReloc{
					instrOffset: offset,
					dispOffset:  dOff,
					instrLen:    inst.Len,
					origDisp:    int32(a),
				})
			}
		}

		offset += inst.Len
	}
	return offset, relocs, nil
}

func findRelOffset(instrBytes []byte, disp int64) (int, bool) {
	d := int32(disp)
	b := [4]byte{byte(d), byte(d >> 8), byte(d >> 16), byte(d >> 24)}
	for i := 0; i <= len(instrBytes)-4; i++ {
		if instrBytes[i] == b[0] && instrBytes[i+1] == b[1] &&
			instrBytes[i+2] == b[2] && instrBytes[i+3] == b[3] {
			return i, true
		}
	}
	return 0, false
}
