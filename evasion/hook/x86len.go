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

func calcStealLength(prologue []byte, minBytes int) (int, error) {
	total := 0
	for total < minBytes {
		if total >= len(prologue) {
			return 0, fmt.Errorf("prologue too short: decoded %d bytes, need %d", total, minBytes)
		}
		inst, err := x86asm.Decode(prologue[total:], 64)
		if err != nil {
			return 0, fmt.Errorf("decode at offset %d: %w", total, err)
		}
		total += inst.Len
	}
	return total, nil
}

func detectRIPRelative(code []byte, stealLen int) ([]ripReloc, error) {
	var relocs []ripReloc
	offset := 0
	for offset < stealLen {
		inst, err := x86asm.Decode(code[offset:], 64)
		if err != nil {
			return nil, fmt.Errorf("decode at offset %d: %w", offset, err)
		}

		for _, arg := range inst.Args {
			switch a := arg.(type) {
			case x86asm.Mem:
				if a.Base != x86asm.RIP {
					continue
				}
				relocs = append(relocs, ripReloc{
					instrOffset: offset,
					dispOffset:  findRelOffset(code[offset:offset+inst.Len], a.Disp),
					instrLen:    inst.Len,
					origDisp:    int32(a.Disp),
				})
			case x86asm.Rel:
				relocs = append(relocs, ripReloc{
					instrOffset: offset,
					dispOffset:  findRelOffset(code[offset:offset+inst.Len], int64(a)),
					instrLen:    inst.Len,
					origDisp:    int32(a),
				})
			}
		}

		offset += inst.Len
	}
	return relocs, nil
}

func findRelOffset(instrBytes []byte, disp int64) int {
	d := int32(disp)
	b := [4]byte{byte(d), byte(d >> 8), byte(d >> 16), byte(d >> 24)}
	for i := 0; i <= len(instrBytes)-4; i++ {
		if instrBytes[i] == b[0] && instrBytes[i+1] == b[1] &&
			instrBytes[i+2] == b[2] && instrBytes[i+3] == b[3] {
			return i
		}
	}
	return len(instrBytes) - 4
}
