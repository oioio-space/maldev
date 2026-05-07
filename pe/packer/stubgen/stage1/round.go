package stage1

import (
	"fmt"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
	"github.com/oioio-space/maldev/pe/packer/stubgen/poly"
)

// Emit writes one decoder loop for the given round into b.
// payloadOffsetLabel must be a label declared in b that points at
// the encoded payload's first byte; payloadLen is the byte count
// the decoder will iterate.
//
// loopLabel is unique per round (the engine passes "loop_0",
// "loop_1", ... "loop_N-1") so multiple chained decoders don't
// collide on a shared label name.
func Emit(b *amd64.Builder, round poly.Round, loopLabel, payloadOffsetLabel string, payloadLen int) error {
	if err := b.MOV(round.CntReg, amd64.Imm(int64(payloadLen))); err != nil {
		return fmt.Errorf("stage1: setup MOV cnt: %w", err)
	}
	if err := b.MOV(round.KeyReg, amd64.Imm(int64(round.Key))); err != nil {
		return fmt.Errorf("stage1: setup MOV key: %w", err)
	}
	// Source pointer is RIP-relative; the host emitter patches the offset
	// after all sections are laid out.
	if err := b.LEA(round.SrcReg, amd64.MemOp{
		RIPRelative: true,
		Label:       payloadOffsetLabel,
	}); err != nil {
		return fmt.Errorf("stage1: setup LEA src: %w", err)
	}

	loop := b.Label(loopLabel)

	// MOVZX, not MOV: a 64-bit load would read 8 bytes instead of 1,
	// corrupting the register's upper bits before the substitution runs.
	if err := b.MOVZX(round.ByteReg, amd64.MemOp{Base: round.SrcReg}); err != nil {
		return fmt.Errorf("stage1: loop MOVZX byte load: %w", err)
	}

	if err := round.Subst.EmitDecoder(b, round.ByteReg, round.Key); err != nil {
		return fmt.Errorf("stage1: subst: %w", err)
	}

	// MOVB, not MOV: a 64-bit store would overwrite 8 bytes of payload,
	// corrupting the 7 bytes following the one we just decoded.
	if err := b.MOVB(amd64.MemOp{Base: round.SrcReg}, round.ByteReg); err != nil {
		return fmt.Errorf("stage1: loop MOVB byte store: %w", err)
	}

	if err := b.ADD(round.SrcReg, amd64.Imm(1)); err != nil {
		return fmt.Errorf("stage1: ADD src 1: %w", err)
	}
	if err := b.DEC(round.CntReg); err != nil {
		return fmt.Errorf("stage1: DEC cnt: %w", err)
	}
	if err := b.JNZ(loop); err != nil {
		return fmt.Errorf("stage1: JNZ loop: %w", err)
	}

	return nil
}
