//go:build windows

package scheduler

import (
	"context"
	"os/exec"
	"syscall"
	"testing"
)

func isAdmin() bool {
	cmd := exec.Command("net", "session")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run() == nil
}

func TestCreateAndDelete(t *testing.T) {
	if !isAdmin() {
		t.Skip("schtasks requires elevation")
	}

	ctx := context.Background()
	const name = `maldev_test_scheduler`

	// Clean up in case a previous test run left debris.
	defer func() {
		_ = Delete(ctx, name)
	}()

	task := &Task{
		Name:    name,
		Command: `C:\Windows\System32\notepad.exe`,
		Trigger: TriggerLogon,
	}

	if err := Create(ctx, task); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if !Exists(ctx, name) {
		t.Fatal("Exists returned false after Create")
	}

	if err := Delete(ctx, name); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if Exists(ctx, name) {
		t.Fatal("Exists returned true after Delete")
	}
}

func TestDeleteNonExistent(t *testing.T) {
	ctx := context.Background()

	err := Delete(ctx, `maldev_test_nonexistent_task`)
	if err == nil {
		t.Fatal("Delete of non-existent task should return error")
	}
}
