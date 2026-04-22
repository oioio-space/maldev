//go:build !windows

package stealthopen

import "testing"

func TestStealthopenStubReturnsErrors(t *testing.T) {
	if _, err := GetObjectID("/tmp/x"); err == nil {
		t.Error("GetObjectID stub must return an error")
	}
	if err := SetObjectID("/tmp/x", [16]byte{}); err == nil {
		t.Error("SetObjectID stub must return an error")
	}
	if _, err := OpenByID("/tmp", [16]byte{}); err == nil {
		t.Error("OpenByID stub must return an error")
	}
}
