package inject

import (
	"fmt"
	"os"
)

const (
	maxShellcodeSize     = 50 * 1024 * 1024 // 50MB
	warningLargeSize     = 10 * 1024 * 1024 // 10MB
	warningSmallSize     = 50               // 50 bytes
	asciiSampleSize      = 100              // sample for text detection
	asciiPrintableThresh = 90               // % ASCII printable threshold
)

// ValidationResult contains the results of shellcode validation.
type ValidationResult struct {
	Valid    bool
	Size     int
	Warnings []string
	Errors   []string
}

// Read reads a shellcode file from disk.
func Read(path string) ([]byte, error) {
	shellcode, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read shellcode: %w", err)
	}
	if len(shellcode) == 0 {
		return nil, fmt.Errorf("shellcode is empty")
	}
	return shellcode, nil
}

// Validate validates a shellcode file before injection.
func Validate(path string) (*ValidationResult, error) {
	result := &ValidationResult{
		Valid:    true,
		Warnings: []string{},
		Errors:   []string{},
	}

	info, err := os.Stat(path)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("file not found: %v", err))
		return result, nil
	}

	result.Size = int(info.Size())

	if result.Size == 0 {
		result.Valid = false
		result.Errors = append(result.Errors, "shellcode is empty")
	}

	if result.Size > maxShellcodeSize {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("file too large (%d MB), probably not shellcode", result.Size/(1024*1024)))
	}

	if result.Size < warningSmallSize {
		result.Warnings = append(result.Warnings, fmt.Sprintf("shellcode very small (%d bytes), verify correctness", result.Size))
	}

	if result.Size > warningLargeSize {
		result.Warnings = append(result.Warnings, fmt.Sprintf("shellcode large (%d MB), might take time to inject", result.Size/(1024*1024)))
	}

	data, err := os.ReadFile(path)
	if err != nil {
		result.Warnings = append(result.Warnings, "could not read file for validation")
		return result, nil
	}

	if len(data) > asciiSampleSize {
		printable := 0
		for i := 0; i < asciiSampleSize; i++ {
			if data[i] >= 32 && data[i] <= 126 {
				printable++
			}
		}
		if printable > asciiPrintableThresh {
			result.Warnings = append(result.Warnings, "file looks like text, not binary shellcode")
		}
	}

	return result, nil
}
