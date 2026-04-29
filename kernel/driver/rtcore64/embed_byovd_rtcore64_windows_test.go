//go:build windows && byovd_rtcore64

package rtcore64

import (
	"testing"
)

// TestLoadDriverBytes_Embedded verifies the byovd_rtcore64-tagged
// build embeds RTCore64.sys and that the bytes carry the expected
// PE signature ("MZ" at offset 0).
func TestLoadDriverBytes_Embedded(t *testing.T) {
	bytes, err := loadDriverBytes()
	if err != nil {
		t.Fatalf("loadDriverBytes() err = %v, want nil", err)
	}
	if len(bytes) < 1024 {
		t.Fatalf("loadDriverBytes() len = %d, want > 1024 (PE driver)", len(bytes))
	}
	if bytes[0] != 'M' || bytes[1] != 'Z' {
		t.Fatalf("loadDriverBytes() head = %02x %02x, want 'M' 'Z'", bytes[0], bytes[1])
	}
}
