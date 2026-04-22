//go:build go1.22

package cmp

import "testing"

func TestCompare(t *testing.T) {
	if Compare(1, 2) != -1 {
		t.Error("Compare(1,2) should be -1")
	}
	if Compare(2, 1) != 1 {
		t.Error("Compare(2,1) should be 1")
	}
	if Compare(3, 3) != 0 {
		t.Error("Compare(3,3) should be 0")
	}
}

func TestLess(t *testing.T) {
	if !Less(1, 2) {
		t.Error("1 should be less than 2")
	}
	if Less(2, 1) {
		t.Error("2 should not be less than 1")
	}
}

func TestOr(t *testing.T) {
	if got := Or(0, 5, 10); got != 5 {
		t.Errorf("Or(0,5,10) = %d, want 5 (first non-zero)", got)
	}
	if got := Or("", "a", "b"); got != "a" {
		t.Errorf("Or('','a','b') = %q, want 'a'", got)
	}
	if got := Or(0); got != 0 {
		t.Errorf("Or(0) = %d, want 0 (zero value)", got)
	}
}
