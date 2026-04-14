package testutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadAllPayloads(t *testing.T) {
	payloads := []struct {
		name    string
		minSize int
	}{
		{"marker_x64.bin", 100},
		{"calc_x64.bin", 100},
		{"msgbox_x64.bin", 100},
		{"meterpreter_x64.bin", 100},
	}

	for _, p := range payloads {
		t.Run(p.name, func(t *testing.T) {
			sc := LoadPayload(t, p.name)
			assert.GreaterOrEqual(t, len(sc), p.minSize,
				"payload %s must be at least %d bytes", p.name, p.minSize)
		})
	}
}
