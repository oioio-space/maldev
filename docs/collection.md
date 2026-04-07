# Collection APIs

[<- Back to README](../README.md)

## collection/keylog -- Keyboard Hook

```go
func Start(ctx context.Context) (<-chan Event, error)
```

**Event** fields: `KeyCode int`, `Character string`, `Window string`, `Process string`, `Time time.Time`

The hook runs until the context is cancelled. The returned channel is closed when the hook is removed.

---

## collection/clipboard -- Clipboard Monitoring

```go
func ReadText() (string, error)
func Watch(ctx context.Context, pollInterval time.Duration) <-chan string
```

`Watch` polls the clipboard sequence number and sends new text content when it changes.

---

## collection/screenshot -- Screen Capture

```go
func Capture() ([]byte, error)
func CaptureRect(x, y, width, height int) ([]byte, error)
func CaptureDisplay(index int) ([]byte, error)
func DisplayCount() int
func DisplayBounds(index int) image.Rectangle
```

Returns PNG-encoded bytes. Multi-monitor support via `DisplayCount`/`DisplayBounds`/`CaptureDisplay`.
