//go:build !windows

package ads

import "testing"

func TestAdsStubReturnsErrors(t *testing.T) {
	if _, err := List("/etc/hosts"); err == nil {
		t.Error("List stub must return an error")
	}
	if _, err := Read("/etc/hosts", "ads"); err == nil {
		t.Error("Read stub must return an error")
	}
	if err := Write("/etc/hosts", "ads", []byte("x")); err == nil {
		t.Error("Write stub must return an error")
	}
	if err := Delete("/etc/hosts", "ads"); err == nil {
		t.Error("Delete stub must return an error")
	}
	if _, err := CreateUndeletable("/tmp", []byte("x")); err == nil {
		t.Error("CreateUndeletable stub must return an error")
	}
	if _, err := ReadUndeletable("/tmp/x"); err == nil {
		t.Error("ReadUndeletable stub must return an error")
	}
}
