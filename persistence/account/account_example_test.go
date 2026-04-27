//go:build windows

package user_test

import (
	"fmt"

	user "github.com/oioio-space/maldev/persistence/account"
)

// Add creates a local account. Requires administrator.
func ExampleAdd() {
	if err := user.Add("svc-update", "P@ssw0rd!2024"); err != nil {
		fmt.Println("add:", err)
	}
}

// SetAdmin promotes an existing account to local Administrators group.
func ExampleSetAdmin() {
	_ = user.SetAdmin("svc-update")
}

// Exists checks for an existing account before mutating.
func ExampleExists() {
	if user.Exists("svc-update") {
		fmt.Println("present")
	}
}

// Delete removes the account.
func ExampleDelete() {
	_ = user.Delete("svc-update")
}
