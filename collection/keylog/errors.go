package keylog

import "errors"

// ErrAlreadyRunning is returned when Start is called while a hook is active.
// Only one keyboard hook per process is supported because the Win32 HOOKPROC
// callback cannot carry closure state.
var ErrAlreadyRunning = errors.New("keyboard hook already running")
