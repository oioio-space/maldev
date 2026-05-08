package stage1_test

import (
	"testing"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
	"github.com/oioio-space/maldev/pe/packer/stubgen/poly"
	"github.com/oioio-space/maldev/pe/packer/stubgen/stage1"
	"github.com/oioio-space/maldev/pe/packer/transform"
)

// stubSizeBudget caps the per-round-count baseline byte count of the emitted
// stub (AntiDebug=false). The numbers were measured at commit d6a1d2b against
// a payload of 0x800 bytes, plan.OEPRVA != plan.TextRVA (so the epilogue ADD
// fires), and seed=42. A 5%-headroom margin is added so a benign
// instruction-encoding tweak in golang-asm doesn't trip the guard.
//
// If a future change pushes the actual size above the budget the fix is
// either:
//   - revert the change if it was unintentional bloat, OR
//   - bump the budget with a commit message that explains why the cost is
//     worth it.
//
// The point is to make stub-size regressions LOUD instead of silent. The
// UPX-style packer's detection profile depends on stub footprint staying
// small; doubling it would shift the signature class.
var stubSizeBudget = map[int]int{
	1: 65,  // measured 61
	3: 145, // measured 137 (3-round baseline operators ship)
	5: 230, // measured 217
	7: 310, // measured 293
}

// stubSizeBudgetAntiDebug is the analogous table for AntiDebug=true stubs.
// The anti-debug prologue adds 82 bytes (measured at this commit, same
// conditions as stubSizeBudget). 5% headroom margin applied.
var stubSizeBudgetAntiDebug = map[int]int{
	1: 155,  // measured 143
	3: 230,  // measured 217
	5: 310,  // measured 293
	7: 400,  // measured 377
}

// TestStubSize_Budget locks the stub byte count per round count so accidental
// bloat (extra fields, wider MOV encodings, fresh junk insertion) gets caught
// at test time. Runs both AntiDebug=false and AntiDebug=true sub-cases.
func TestStubSize_Budget(t *testing.T) {
	plan := transform.Plan{
		Format:   transform.FormatPE,
		TextRVA:  0x1000,
		TextSize: 0x800,
		OEPRVA:   0x1100, // != TextRVA so the epilogue ADD oepDisp fires
		StubRVA:  0x10000,
	}

	for rounds, budget := range stubSizeBudget {
		t.Run("", func(t *testing.T) {
			out := emitForBudget(t, plan, rounds, stage1.EmitOptions{})
			if got := len(out); got > budget {
				t.Errorf("rounds=%d AntiDebug=false stub size = %d bytes, budget %d",
					rounds, got, budget)
			}
		})
	}

	for rounds, budget := range stubSizeBudgetAntiDebug {
		t.Run("", func(t *testing.T) {
			out := emitForBudget(t, plan, rounds, stage1.EmitOptions{AntiDebug: true})
			if got := len(out); got > budget {
				t.Errorf("rounds=%d AntiDebug=true stub size = %d bytes, budget %d",
					rounds, got, budget)
			}
		})
	}
}

// emitForBudget assembles a stub and patches the sentinel; used by the budget
// table tests to avoid repeating the boilerplate four times.
func emitForBudget(t *testing.T, plan transform.Plan, rounds int, opts stage1.EmitOptions) []byte {
	t.Helper()
	eng, err := poly.NewEngine(42, rounds)
	if err != nil {
		t.Fatalf("rounds=%d NewEngine: %v", rounds, err)
	}
	_, descs, err := eng.EncodePayloadExcluding([]byte("budget test payload"), stage1.BaseReg)
	if err != nil {
		t.Fatalf("rounds=%d EncodePayload: %v", rounds, err)
	}
	b, err := amd64.New()
	if err != nil {
		t.Fatalf("rounds=%d amd64.New: %v", rounds, err)
	}
	if err := stage1.EmitStub(b, plan, descs, opts); err != nil {
		t.Fatalf("rounds=%d EmitStub: %v", rounds, err)
	}
	out, err := b.Encode()
	if err != nil {
		t.Fatalf("rounds=%d Encode: %v", rounds, err)
	}
	if _, err := stage1.PatchTextDisplacement(out, plan); err != nil {
		t.Fatalf("rounds=%d Patch: %v", rounds, err)
	}
	return out
}
