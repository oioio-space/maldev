// Package timing provides time-based evasion detection techniques.
// These defeat sandbox analysis that fast-forwards Sleep() calls.
package timing

import "time"

// BusyWait burns CPU for the specified duration without calling Sleep.
// Defeats sandbox hooks on NtDelayExecution/Sleep that fast-forward time.
func BusyWait(d time.Duration) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		// intentional CPU burn
	}
}

// BusyWaitPrimality burns CPU using primality testing (harder to detect than simple loop).
// Tests ~500,000 numbers for primality — takes approximately 200ms on modern hardware.
func BusyWaitPrimality() {
	count := 0
	for n := 2; count < 500000; n++ {
		isPrime := true
		for i := 2; i*i <= n; i++ {
			if n%i == 0 {
				isPrime = false
				break
			}
		}
		if isPrime {
			count++
		}
	}
}
