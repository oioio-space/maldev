//go:build windows

package user

import (
	"errors"
	"os"
	"testing"
)

func TestIsAdmin(t *testing.T) {
	// Smoke test: must not panic, must return a bool.
	admin := IsAdmin()
	t.Logf("IsAdmin = %v", admin)
}

func TestList(t *testing.T) {
	users, err := List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(users) == 0 {
		t.Fatal("List returned zero users; expected at least one")
	}
	t.Logf("found %d local users", len(users))
}

func TestExists(t *testing.T) {
	name := os.Getenv("USERNAME")
	if name == "" {
		t.Skip("USERNAME not set")
	}
	if !Exists(name) {
		t.Errorf("Exists(%q) = false; expected true for current user", name)
	}
}

func TestExistsNonexistent(t *testing.T) {
	// A username this long and random should never exist.
	if Exists("zzz_nonexistent_test_user_9f3a1b") {
		t.Error("Exists returned true for a user that should not exist")
	}
}

func TestAddAccessDenied(t *testing.T) {
	if IsAdmin() {
		t.Skip("running as admin; skipping to avoid creating a real user")
	}

	err := Add("zzz_test_user_no_create", "Test@1234!")
	if err == nil {
		t.Fatal("Add succeeded without admin; expected error")
	}
	if !errors.Is(err, ErrAccessDenied) {
		t.Errorf("Add error = %v; expected ErrAccessDenied", err)
	}
}
