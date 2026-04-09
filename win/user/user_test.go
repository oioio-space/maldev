//go:build windows

package user

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/windows"
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

// TestAddDeleteLifecycle creates a user, verifies it exists, then deletes it.
func TestAddDeleteLifecycle(t *testing.T) {
	if !IsAdmin() {
		t.Skip("requires admin")
	}
	if os.Getenv("MALDEV_MANUAL") == "" {
		t.Skip("manual test: set MALDEV_MANUAL=1")
	}

	const name = "maldev_test_user"
	const pass = "T3st@Pass!99"

	// Cleanup in case previous run left it behind.
	Delete(name)

	if err := Add(name, pass); err != nil {
		t.Fatalf("Add: %v", err)
	}
	defer Delete(name)

	if !Exists(name) {
		t.Fatal("user was created but Exists returns false")
	}

	// SetPassword
	if err := SetPassword(name, "N3w@Pass!88"); err != nil {
		t.Errorf("SetPassword: %v", err)
	}

	// SetAdmin / RevokeAdmin
	if err := SetAdmin(name); err != nil {
		t.Errorf("SetAdmin: %v", err)
	}
	if err := RevokeAdmin(name); err != nil {
		t.Errorf("RevokeAdmin: %v", err)
	}

	// AddToGroup / RemoveFromGroup — resolve the localized Users group name
	// via its well-known SID (locale-independent).
	usersSID, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Logf("skipping AddToGroup/RemoveFromGroup: cannot create Users SID: %v", err)
	} else {
		usersGroup, _, _, err := usersSID.LookupAccount("")
		if err != nil {
			t.Logf("skipping AddToGroup/RemoveFromGroup: cannot resolve Users SID: %v", err)
		} else {
			if err := AddToGroup(name, usersGroup); err != nil {
				t.Errorf("AddToGroup(%q): %v", usersGroup, err)
			}
			if err := RemoveFromGroup(name, usersGroup); err != nil {
				t.Errorf("RemoveFromGroup(%q): %v", usersGroup, err)
			}
		}
	}

	// Delete
	if err := Delete(name); err != nil {
		t.Errorf("Delete: %v", err)
	}
	if Exists(name) {
		t.Error("user still exists after Delete")
	}
}

// TestDeleteNonexistent verifies deleting a non-existent user returns an error.
func TestDeleteNonexistent(t *testing.T) {
	err := Delete("zzz_nonexistent_user_999")
	if err == nil {
		t.Error("Delete of non-existent user should return error")
	}
}
