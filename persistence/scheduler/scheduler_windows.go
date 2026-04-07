//go:build windows

package scheduler

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"syscall"
)

// ErrTaskCreate is returned when task creation fails.
var ErrTaskCreate = errors.New("failed to create scheduled task")

// ErrTaskDelete is returned when task deletion fails.
var ErrTaskDelete = errors.New("failed to delete scheduled task")

// Trigger defines when a scheduled task runs.
type Trigger int

const (
	TriggerLogon   Trigger = iota // Run at user logon (requires elevation)
	TriggerStartup                // Run at system startup (requires elevation)
	TriggerDaily                  // Run daily
)

// triggerFlag maps a Trigger to its schtasks /SC parameter value.
func triggerFlag(t Trigger) string {
	switch t {
	case TriggerStartup:
		return "ONSTART"
	case TriggerDaily:
		return "DAILY"
	default:
		return "ONLOGON"
	}
}

// Task configures a scheduled task.
type Task struct {
	Name    string  // Task name (supports backslash for folders: "Folder\TaskName")
	Command string  // Command to execute
	Args    string  // Command-line arguments
	Trigger Trigger // When to run
}

// Create registers a scheduled task via schtasks.exe.
func Create(ctx context.Context, task *Task) error {
	if task.Name == "" {
		return fmt.Errorf("task name must not be empty")
	}
	if task.Command == "" {
		return fmt.Errorf("task command must not be empty")
	}

	args := []string{
		"/Create",
		"/TN", task.Name,
		"/TR", buildTR(task.Command, task.Args),
		"/SC", triggerFlag(task.Trigger),
		"/F", // force overwrite if exists
	}

	if err := runSchtasks(ctx, args); err != nil {
		return fmt.Errorf("%w: %w", ErrTaskCreate, err)
	}
	return nil
}

// Delete removes a scheduled task.
func Delete(ctx context.Context, name string) error {
	args := []string{
		"/Delete",
		"/TN", name,
		"/F", // suppress confirmation prompt
	}
	if err := runSchtasks(ctx, args); err != nil {
		return fmt.Errorf("%w: %w", ErrTaskDelete, err)
	}
	return nil
}

// Exists checks if a scheduled task exists.
func Exists(ctx context.Context, name string) bool {
	args := []string{
		"/Query",
		"/TN", name,
	}
	return runSchtasks(ctx, args) == nil
}

// buildTR constructs the /TR value, quoting the command path to handle
// spaces in directory names (e.g., "C:\Program Files\...").
func buildTR(command, args string) string {
	quoted := `"` + command + `"`
	if args == "" {
		return quoted
	}
	return quoted + " " + args
}

// runSchtasks executes schtasks.exe with a hidden console window.
func runSchtasks(ctx context.Context, args []string) error {
	cmd := exec.CommandContext(ctx, "schtasks.exe", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}
