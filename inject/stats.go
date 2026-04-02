package inject

import (
	"fmt"
	"io"
	"os"
	"time"
)

// InjectionStats contains statistics for an injection attempt.
type InjectionStats struct {
	Method        Method
	ShellcodeSize int
	TargetPID     int
	StartTime     time.Time
	Duration      time.Duration
	Success       bool
	Error         error
}

// NewInjectionStats creates a new stats instance.
func NewInjectionStats(method Method, shellcodeSize int, targetPID int) *InjectionStats {
	return &InjectionStats{
		Method:        method,
		ShellcodeSize: shellcodeSize,
		TargetPID:     targetPID,
		StartTime:     time.Now(),
	}
}

// Finish marks the injection as completed.
func (s *InjectionStats) Finish(err error) {
	s.Duration = time.Since(s.StartTime)
	s.Success = err == nil
	s.Error = err
}

// Fprint writes the injection statistics to w.
func (s *InjectionStats) Fprint(w io.Writer) {
	if s.Success {
		fmt.Fprintf(w, "\n[SUCCESS] Injection completed in %.2fs\n", s.Duration.Seconds())
	} else {
		fmt.Fprintf(w, "\n[FAILED] Injection failed after %.2fs\n", s.Duration.Seconds())
		if s.Error != nil {
			fmt.Fprintf(w, "  Error: %v\n", s.Error)
		}
		return
	}

	fmt.Fprintf(w, "  Method: %s\n", s.Method)
	fmt.Fprintf(w, "  Shellcode: %d bytes\n", s.ShellcodeSize)

	if s.TargetPID > 0 {
		fmt.Fprintf(w, "  Target: PID %d\n", s.TargetPID)
	} else {
		fmt.Fprintf(w, "  Target: Current process\n")
	}
}

// Print writes the injection statistics to stdout.
func (s *InjectionStats) Print() {
	s.Fprint(os.Stdout)
}
