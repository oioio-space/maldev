package dllhijack

import (
	"strings"
	"testing"
)

// TestPickBestWritableFrom_PrefersIntegrityGain asserts the selector
// returns a writable+IntegrityGain Opportunity over a higher-scoring
// writable-only one. Rank-order is honoured within the integrity-gain
// tier (descending Score).
func TestPickBestWritableFrom_PrefersIntegrityGain(t *testing.T) {
	// Already-ranked input (callers feed Rank's output). Lower
	// in the slice = lower priority by convention here.
	ranked := []Opportunity{
		{HijackedDLL: "a.dll", Writable: true, Score: 50},                    // writable only
		{HijackedDLL: "b.dll", Writable: true, IntegrityGain: true, Score: 1}, // integrity-gain but low score
	}
	got := pickBestWritableFrom(ranked)
	if got == nil || got.HijackedDLL != "b.dll" {
		t.Fatalf("got %v, want IntegrityGain candidate b.dll", got)
	}
}

func TestPickBestWritableFrom_FallbackToAnyWritable(t *testing.T) {
	ranked := []Opportunity{
		{HijackedDLL: "no-write.dll", Writable: false, IntegrityGain: true, Score: 300},
		{HijackedDLL: "any.dll", Writable: true, Score: 50},
	}
	got := pickBestWritableFrom(ranked)
	if got == nil || got.HijackedDLL != "any.dll" {
		t.Fatalf("got %v, want fallback any.dll", got)
	}
}

func TestPickBestWritableFrom_NilOnAllReadOnly(t *testing.T) {
	ranked := []Opportunity{
		{HijackedDLL: "a.dll", Writable: false},
		{HijackedDLL: "b.dll", Writable: false, IntegrityGain: true},
	}
	if got := pickBestWritableFrom(ranked); got != nil {
		t.Fatalf("got %v, want nil when nothing is writable", got)
	}
}

func TestPickBestWritableFrom_NilOnEmpty(t *testing.T) {
	if got := pickBestWritableFrom(nil); got != nil {
		t.Fatalf("got %v, want nil on empty input", got)
	}
}

func TestPickBestWritableFrom_PrefersAutoElevate(t *testing.T) {
	ranked := []Opportunity{
		{HijackedDLL: "plain.dll", Writable: true, Score: 100},
		{HijackedDLL: "ae.dll", Writable: true, AutoElevate: true, Score: 1},
	}
	got := pickBestWritableFrom(ranked)
	if got == nil || got.HijackedDLL != "ae.dll" {
		t.Fatalf("got %v, want AutoElevate candidate ae.dll", got)
	}
}

// TestPickBestWritable_NonWindowsSurfacesScanError exercises the
// exported entry point on non-Windows so the sentinel-wrapping error
// path is covered by CI. Windows hosts skip this case (ScanAll there
// returns real data).
func TestPickBestWritable_NonWindowsSurfacesScanError(t *testing.T) {
	_, err := PickBestWritable()
	if err == nil {
		// ScanAll stub returns an error on non-windows; on windows
		// hosts the call may legitimately succeed → just skip.
		t.Skip("ScanAll succeeded — Windows host, sentinel path not exercised here")
	}
	// On non-windows the wrapped error must mention "PickBestWritable scan".
	if !strings.Contains(err.Error(), "PickBestWritable scan") {
		t.Fatalf("error %q missing 'PickBestWritable scan' wrapper", err)
	}
}
