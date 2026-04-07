package persistence

import (
	"errors"
	"testing"
)

type mockMechanism struct {
	name       string
	installErr error
	installed  bool
}

func (m *mockMechanism) Name() string            { return m.name }
func (m *mockMechanism) Install() error           { return m.installErr }
func (m *mockMechanism) Uninstall() error         { return nil }
func (m *mockMechanism) Installed() (bool, error) { return m.installed, nil }

func TestInstallAll_Empty(t *testing.T) {
	errs := InstallAll(nil)
	if errs != nil {
		t.Fatal("expected nil for empty slice")
	}
}

func TestInstallAll_Success(t *testing.T) {
	m := []Mechanism{&mockMechanism{name: "test"}}
	errs := InstallAll(m)
	if errs != nil {
		t.Fatalf("expected nil, got %v", errs)
	}
}

func TestInstallAll_PartialFailure(t *testing.T) {
	m := []Mechanism{
		&mockMechanism{name: "ok"},
		&mockMechanism{name: "fail", installErr: errors.New("boom")},
	}
	errs := InstallAll(m)
	if errs == nil {
		t.Fatal("expected errors")
	}
	if _, ok := errs["fail"]; !ok {
		t.Fatal("expected 'fail' in error map")
	}
	if _, ok := errs["ok"]; ok {
		t.Fatal("'ok' should not be in error map")
	}
}

func TestUninstallAll_Empty(t *testing.T) {
	errs := UninstallAll(nil)
	if errs != nil {
		t.Fatal("expected nil")
	}
}
