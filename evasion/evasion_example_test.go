package evasion_test

import (
	"fmt"

	"github.com/oioio-space/maldev/evasion"
)

type noopTechnique struct{ name string }

func (t noopTechnique) Name() string                  { return t.name }
func (t noopTechnique) Apply(c evasion.Caller) error  { return nil }

// ApplyAll runs every supplied [Technique] in order with the same
// Caller and returns a per-name error map (nil → success).
// Operators chain a stack of evasions before any noisy operation
// (injection, BOF load, LSASS dump …).
func ExampleApplyAll() {
	stack := []evasion.Technique{
		noopTechnique{name: "amsi"},
		noopTechnique{name: "etw"},
		noopTechnique{name: "unhook"},
	}
	results := evasion.ApplyAll(stack, nil) // nil Caller = standard WinAPI
	for name, err := range results {
		if err != nil {
			fmt.Printf("%s: %v\n", name, err)
		}
	}
}
