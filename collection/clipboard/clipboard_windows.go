//go:build windows

package clipboard

import (
	"context"
	"errors"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/win/api"
)

const cfUnicodeText = 13

var (
	procOpenClipboard              = api.User32.NewProc("OpenClipboard")
	procCloseClipboard             = api.User32.NewProc("CloseClipboard")
	procGetClipboardData           = api.User32.NewProc("GetClipboardData")
	procIsClipboardFormatAvailable = api.User32.NewProc("IsClipboardFormatAvailable")
	procGetClipboardSequenceNumber = api.User32.NewProc("GetClipboardSequenceNumber")

	procGlobalLock   = api.Kernel32.NewProc("GlobalLock")
	procGlobalUnlock = api.Kernel32.NewProc("GlobalUnlock")
)

// ErrOpen is returned when the clipboard cannot be opened.
var ErrOpen = errors.New("clipboard open failed")

// minPollInterval prevents excessive polling.
const minPollInterval = 100 * time.Millisecond

// ReadText reads the current clipboard text content.
// Returns empty string if the clipboard is empty or does not contain text.
func ReadText() (string, error) {
	r, _, _ := procOpenClipboard.Call(0)
	if r == 0 {
		return "", ErrOpen
	}
	defer procCloseClipboard.Call() //nolint:errcheck

	r, _, _ = procIsClipboardFormatAvailable.Call(cfUnicodeText)
	if r == 0 {
		return "", nil
	}

	h, _, _ := procGetClipboardData.Call(cfUnicodeText)
	if h == 0 {
		return "", nil
	}

	ptr, _, _ := procGlobalLock.Call(h)
	if ptr == 0 {
		return "", nil
	}
	defer procGlobalUnlock.Call(h) //nolint:errcheck

	// Convert the null-terminated UTF-16 string to Go string.
	text := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(ptr)))
	return text, nil
}

// Watch monitors the clipboard for text changes and sends new content
// to the returned channel. The channel is closed when the context is
// cancelled. pollInterval controls how often to check for changes;
// values below 100ms are clamped.
func Watch(ctx context.Context, pollInterval time.Duration) <-chan string {
	if pollInterval < minPollInterval {
		pollInterval = minPollInterval
	}

	ch := make(chan string, 16)

	go func() {
		defer close(ch)

		// Seed with the current sequence number so we only send changes.
		lastSeq, _, _ := procGetClipboardSequenceNumber.Call()

		ticker := time.NewTicker(pollInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				seq, _, _ := procGetClipboardSequenceNumber.Call()
				if seq == lastSeq {
					continue
				}
				lastSeq = seq

				text, err := ReadText()
				if err != nil || text == "" {
					continue
				}

				select {
				case ch <- text:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return ch
}
