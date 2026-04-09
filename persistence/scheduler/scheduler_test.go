//go:build windows

package scheduler

import (
	"context"
	"testing"

	"github.com/oioio-space/maldev/win/user"
)

func TestCreateAndDelete(t *testing.T) {
	if !user.IsAdmin() {
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

func TestExistsNonExistent(t *testing.T) {
	ctx := context.Background()
	if Exists(ctx, `maldev_zzz_nonexistent_task_999`) {
		t.Error("Exists returned true for non-existent task")
	}
}

func TestScheduledTaskMechanism(t *testing.T) {
	task := &Task{
		Name:    "maldev_test_mech",
		Command: `C:\Windows\System32\notepad.exe`,
		Trigger: TriggerLogon,
	}
	mech := ScheduledTask(task)
	if mech == nil {
		t.Fatal("ScheduledTask returned nil")
	}
}

func TestTriggerLogonConstant(t *testing.T) {
	// TriggerLogon should be the zero value (iota).
	if TriggerLogon != 0 {
		t.Errorf("TriggerLogon = %d; expected 0", TriggerLogon)
	}
}

func TestDeleteNonExistent(t *testing.T) {
	ctx := context.Background()

	err := Delete(ctx, `maldev_test_nonexistent_task`)
	if err == nil {
		t.Fatal("Delete of non-existent task should return error")
	}
}
