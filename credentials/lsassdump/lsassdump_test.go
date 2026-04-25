package lsassdump

import "testing"

// TestStatsZeroValue pins the Stats zero value so later callers and
// JSON encoders don't silently re-order or rename fields.
func TestStatsZeroValue(t *testing.T) {
	var s Stats
	if s.Regions != 0 || s.Bytes != 0 || s.ModuleCount != 0 || s.ThreadCount != 0 {
		t.Fatalf("Stats zero value should be all-zero, got %+v", s)
	}
}
