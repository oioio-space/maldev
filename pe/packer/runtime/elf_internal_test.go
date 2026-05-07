package runtime

// White-box tests for elfHeaders internals that are not yet wired into
// the public Prepare path (gateRejectionReason, hasDTNeeded). These
// exercise the diagnostic machinery introduced in the Task 1 review fix
// so regressions surface before Task 6 wires the gate into ValidateELF.

import (
	"encoding/binary"
	"strings"
	"testing"
)

// buildNeededELF returns a minimal ET_DYN ELF byte slice that carries
// one DT_NEEDED entry in its PT_DYNAMIC section. Used to verify
// hasDTNeeded is set and gateRejectionReason names DT_NEEDED.
func buildNeededELF(t *testing.T) []byte {
	t.Helper()

	const (
		ehdrSize = 64
		phdrSize = 56
		phnum    = 2  // PT_LOAD + PT_DYNAMIC
		dynSize  = 32 // DT_NEEDED(16 bytes) + DT_NULL(16 bytes)
	)
	totalSize := ehdrSize + phnum*phdrSize + dynSize
	dynOff := ehdrSize + phnum*phdrSize

	out := make([]byte, totalSize)

	// ELF ident
	out[0], out[1], out[2], out[3] = 0x7F, 'E', 'L', 'F'
	out[4] = 2 // ELFCLASS64
	out[5] = 1 // ELFDATA2LSB
	out[6] = 1 // EV_CURRENT

	le := binary.LittleEndian
	le.PutUint16(out[16:], 3)          // e_type = ET_DYN
	le.PutUint16(out[18:], 62)         // e_machine = EM_X86_64
	le.PutUint32(out[20:], 1)          // e_version
	le.PutUint64(out[32:], ehdrSize)   // e_phoff
	le.PutUint16(out[54:], phdrSize)   // e_phentsize
	le.PutUint16(out[56:], phnum)      // e_phnum

	// PT_LOAD covering the whole file
	off := ehdrSize
	le.PutUint32(out[off:], 1)                    // p_type = PT_LOAD
	le.PutUint32(out[off+4:], 5)                  // p_flags = PF_R|PF_X
	le.PutUint64(out[off+8:], 0)                  // p_offset
	le.PutUint64(out[off+16:], 0)                 // p_vaddr
	le.PutUint64(out[off+24:], 0)                 // p_paddr
	le.PutUint64(out[off+32:], uint64(totalSize)) // p_filesz
	le.PutUint64(out[off+40:], uint64(totalSize)) // p_memsz
	le.PutUint64(out[off+48:], 0x1000)            // p_align
	off += phdrSize

	// PT_DYNAMIC pointing at the DT_NEEDED + DT_NULL body
	le.PutUint32(out[off:], 2)                   // p_type = PT_DYNAMIC
	le.PutUint32(out[off+4:], 6)                 // p_flags = PF_R|PF_W
	le.PutUint64(out[off+8:], uint64(dynOff))    // p_offset
	le.PutUint64(out[off+16:], uint64(dynOff))   // p_vaddr
	le.PutUint64(out[off+24:], uint64(dynOff))   // p_paddr
	le.PutUint64(out[off+32:], 32)               // p_filesz
	le.PutUint64(out[off+40:], 32)               // p_memsz
	le.PutUint64(out[off+48:], 8)                // p_align

	// Dynamic section: DT_NEEDED(tag=1, val=0) then DT_NULL.
	// dynamicHasNoNeeded stops at the DT_NEEDED entry and returns false.
	le.PutUint64(out[dynOff:], 1)   // DT_NEEDED tag
	le.PutUint64(out[dynOff+8:], 0) // d_val (string-table offset; irrelevant for detection)
	// out[dynOff+16..+32] stays zero — DT_NULL sentinel

	return out
}

// buildInterpELF returns a minimal ET_DYN ELF with a PT_INTERP phdr.
// Used to confirm PT_INTERP is reported by gateRejectionReason before
// the ET_DYN / DT_NEEDED checks.
func buildInterpELF(t *testing.T) []byte {
	t.Helper()

	const (
		ehdrSize = 64
		phdrSize = 56
		phnum    = 2 // PT_LOAD + PT_INTERP
	)
	out := make([]byte, ehdrSize+phnum*phdrSize)

	out[0], out[1], out[2], out[3] = 0x7F, 'E', 'L', 'F'
	out[4] = 2; out[5] = 1; out[6] = 1

	le := binary.LittleEndian
	le.PutUint16(out[16:], 3)        // e_type = ET_DYN
	le.PutUint16(out[18:], 62)       // e_machine = EM_X86_64
	le.PutUint32(out[20:], 1)        // e_version
	le.PutUint64(out[32:], ehdrSize) // e_phoff
	le.PutUint16(out[54:], phdrSize) // e_phentsize
	le.PutUint16(out[56:], phnum)    // e_phnum

	off := ehdrSize
	le.PutUint32(out[off:], 1); le.PutUint32(out[off+4:], 5) // PT_LOAD, PF_R|PF_X
	off += phdrSize
	le.PutUint32(out[off:], 3); le.PutUint32(out[off+4:], 4) // PT_INTERP, PF_R

	return out
}

// TestGateRejectionReason_DTNeeded confirms that an ET_DYN binary with
// DT_NEEDED entries populates hasDTNeeded and that gateRejectionReason
// surfaces "DT_NEEDED" rather than the old "no .go.buildinfo" fallback.
func TestGateRejectionReason_DTNeeded(t *testing.T) {
	raw := buildNeededELF(t)
	h, err := parseELFHeaders(raw)
	if err != nil {
		t.Fatalf("parseELFHeaders: %v", err)
	}
	if !h.HasDTNeeded {
		t.Fatal("hasDTNeeded should be true for an ELF with DT_NEEDED entries")
	}
	if h.IsStaticPIE {
		t.Fatal("IsStaticPIE should be false when DT_NEEDED is present")
	}
	reason := h.GateRejectionReason()
	if reason == "" {
		t.Fatal("gateRejectionReason returned empty string for a non-static-PIE binary")
	}
	if !strings.Contains(reason, "DT_NEEDED") {
		t.Errorf("gateRejectionReason = %q; want it to mention DT_NEEDED", reason)
	}
}

// TestGateRejectionReason_Precedence verifies the structural
// rejection ordering: ET_DYN > DT_NEEDED. After Stage E broadened
// the gate to drop the .go.buildinfo requirement, a binary that
// passes both structural checks (ET_DYN + no DT_NEEDED) is
// accepted — IsStaticPIE is true, GateRejectionReason returns "".
func TestGateRejectionReason_Precedence(t *testing.T) {
	t.Run("PT_INTERP alone is accepted (no rejection)", func(t *testing.T) {
		// A minimal ET_DYN + PT_INTERP binary with no DT_NEEDED:
		// passes structural gate; rejection reason is empty.
		h, err := parseELFHeaders(buildInterpELF(t))
		if err != nil {
			t.Fatalf("parseELFHeaders: %v", err)
		}
		if !h.IsStaticPIE {
			t.Errorf("IsStaticPIE = false; ET_DYN + PT_INTERP without DT_NEEDED must pass Stage E gate")
		}
		if reason := h.GateRejectionReason(); reason != "" {
			t.Errorf("gateRejectionReason = %q; expected empty for accepted binary", reason)
		}
	})

	t.Run("DT_NEEDED is the primary rejection signal", func(t *testing.T) {
		h, err := parseELFHeaders(buildNeededELF(t))
		if err != nil {
			t.Fatalf("parseELFHeaders: %v", err)
		}
		reason := h.GateRejectionReason()
		if !strings.Contains(reason, "DT_NEEDED") {
			t.Errorf("gateRejectionReason = %q; want DT_NEEDED rejection", reason)
		}
	})
}
