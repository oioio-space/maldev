package injection

import (
	"fmt"
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

// Print displays the statistics.
func (s *InjectionStats) Print() {
	if s.Success {
		fmt.Printf("\n[SUCCESS] Injection completed in %.2fs\n", s.Duration.Seconds())
	} else {
		fmt.Printf("\n[FAILED] Injection failed after %.2fs\n", s.Duration.Seconds())
		if s.Error != nil {
			fmt.Printf("  Error: %v\n", s.Error)
		}
		return
	}

	fmt.Printf("  Method: %s\n", s.Method)
	fmt.Printf("  Shellcode: %d bytes\n", s.ShellcodeSize)

	if s.TargetPID > 0 {
		fmt.Printf("  Target: PID %d\n", s.TargetPID)
	} else {
		fmt.Printf("  Target: Current process\n")
	}
}
