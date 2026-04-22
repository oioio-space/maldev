//go:build go1.21

package slices

import "testing"

// Smoke tests for the Go ≥1.21 pass-through wrappers. Stdlib correctness is
// already tested upstream; these exist so the package shows up in coverage.

func TestContains(t *testing.T) {
	if !Contains([]int{1, 2, 3}, 2) {
		t.Error("expected 2 to be contained")
	}
	if Contains([]int{1, 2, 3}, 4) {
		t.Error("expected 4 to be absent")
	}
}

func TestIndex(t *testing.T) {
	if Index([]string{"a", "b", "c"}, "b") != 1 {
		t.Error("expected index 1")
	}
	if Index([]string{"a"}, "z") != -1 {
		t.Error("expected -1 for missing")
	}
}

func TestEqual(t *testing.T) {
	if !Equal([]int{1, 2}, []int{1, 2}) {
		t.Error("should be equal")
	}
	if Equal([]int{1, 2}, []int{1, 3}) {
		t.Error("should not be equal")
	}
}

func TestReverse(t *testing.T) {
	s := []int{1, 2, 3}
	Reverse(s)
	if s[0] != 3 || s[2] != 1 {
		t.Errorf("reverse failed: %v", s)
	}
}

func TestSortAndSortFunc(t *testing.T) {
	s := []int{3, 1, 2}
	Sort(s)
	if !Equal(s, []int{1, 2, 3}) {
		t.Errorf("Sort failed: %v", s)
	}
	SortFunc(s, func(a, b int) int { return b - a })
	if !Equal(s, []int{3, 2, 1}) {
		t.Errorf("SortFunc desc failed: %v", s)
	}
}

func TestCompact(t *testing.T) {
	if got := Compact([]int{1, 1, 2, 2, 3}); !Equal(got, []int{1, 2, 3}) {
		t.Errorf("Compact = %v", got)
	}
}

func TestClone(t *testing.T) {
	orig := []int{1, 2, 3}
	c := Clone(orig)
	if !Equal(c, orig) {
		t.Error("clone content diverged")
	}
	c[0] = 99
	if orig[0] == 99 {
		t.Error("clone should not share backing array")
	}
}

func TestContainsFunc(t *testing.T) {
	if !ContainsFunc([]int{1, 2, 3}, func(n int) bool { return n == 2 }) {
		t.Error("expected match via predicate")
	}
	if ContainsFunc([]int{1, 2, 3}, func(n int) bool { return n > 10 }) {
		t.Error("unexpected match via predicate")
	}
}

func TestEqualFunc(t *testing.T) {
	if !EqualFunc([]int{1, 2}, []string{"1", "2"}, func(a int, b string) bool {
		return (a == 1 && b == "1") || (a == 2 && b == "2")
	}) {
		t.Error("EqualFunc should match")
	}
}

func TestClipAndGrow(t *testing.T) {
	s := make([]int, 3, 10)
	Clip(s) // just exercise the path — return is unused, coverage only
	// Grow(s, n) guarantees cap >= len(s)+n; may be a no-op if already sized.
	s2 := make([]int, 3, 3)
	got := Grow(s2, 5)
	if cap(got) < len(s2)+5 {
		t.Errorf("Grow cap %d < len(%d)+5", cap(got), len(s2))
	}
}
