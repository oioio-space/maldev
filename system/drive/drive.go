//go:build windows

package drive

import (
	"context"
	"fmt"
	"time"
)

// Type represents a Windows drive type (DRIVE_* constants from MSDN).
type Type uint32

const (
	TypeUnknown   Type = 0 // DRIVE_UNKNOWN
	TypeNoRootDir Type = 1 // DRIVE_NO_ROOT_DIR
	TypeRemovable Type = 2 // DRIVE_REMOVABLE
	TypeFixed     Type = 3 // DRIVE_FIXED
	TypeRemote    Type = 4 // DRIVE_REMOTE
	TypeCDROM     Type = 5 // DRIVE_CDROM
	TypeRAMDisk   Type = 6 // DRIVE_RAMDISK
)

// String returns the MSDN constant name for the drive type.
func (t Type) String() string {
	switch t {
	case TypeUnknown:
		return "DRIVE_UNKNOWN"
	case TypeNoRootDir:
		return "DRIVE_NO_ROOT_DIR"
	case TypeRemovable:
		return "DRIVE_REMOVABLE"
	case TypeFixed:
		return "DRIVE_FIXED"
	case TypeRemote:
		return "DRIVE_REMOTE"
	case TypeCDROM:
		return "DRIVE_CDROM"
	case TypeRAMDisk:
		return "DRIVE_RAMDISK"
	default:
		return fmt.Sprintf("DRIVE_TYPE(%d)", t)
	}
}

// VolumeInfo contains volume metadata from GetVolumeInformationW.
type VolumeInfo struct {
	Name           string
	SerialNumber   uint32
	FileSystemName string
}

// Info represents a detected disk drive. The GUID field is the canonical
// unique identifier (stable across reboots and letter reassignments).
type Info struct {
	Letter     string     // "C:\\"
	Type       Type       // DRIVE_FIXED, DRIVE_REMOVABLE, etc.
	Volume     *VolumeInfo
	GUID       string     // \\?\Volume{...}\ — stable unique ID
	DevicePath string     // \Device\HarddiskVolumeN
}

// New creates an Info from a drive letter (e.g., "C:\\").
func New(letter string) (*Info, error) {
	vol, err := VolumeOf(letter)
	if err != nil {
		return nil, err
	}
	return &Info{
		Letter:     letter,
		Type:       TypeOf(letter),
		Volume:     vol,
		GUID:       volumeGUID(letter),
		DevicePath: devicePath(letter),
	}, nil
}

// FilterFunc is a predicate for filtering drives.
type FilterFunc func(d *Info) bool

// EventKind identifies what happened to a drive.
type EventKind int

const (
	EventAdded   EventKind = iota // Drive was connected
	EventRemoved                  // Drive was disconnected
)

func (k EventKind) String() string {
	switch k {
	case EventAdded:
		return "added"
	case EventRemoved:
		return "removed"
	default:
		return fmt.Sprintf("EventKind(%d)", k)
	}
}

// Event is emitted by Watcher when a drive change is detected.
type Event struct {
	Kind  EventKind
	Drive *Info  // non-nil for Added/Removed events
	Err   error  // non-nil when enumeration failed
}

// Watcher monitors drive changes using the Observer pattern.
// It polls GetLogicalDrives for bitmask changes, then enumerates
// only the affected letters. Events are delivered on a typed channel.
type Watcher struct {
	known  map[string]*Info // keyed by GUID (stable ID)
	ctx    context.Context
	filter FilterFunc
}

// NewWatcher creates a Watcher that monitors drives matching the filter.
// The context controls the watcher goroutine's lifetime.
func NewWatcher(ctx context.Context, filter FilterFunc) *Watcher {
	return &Watcher{
		known:  make(map[string]*Info),
		ctx:    ctx,
		filter: filter,
	}
}

// Snapshot returns all current drives matching the filter.
// Does not start monitoring — use Watch for that.
func (w *Watcher) Snapshot() ([]*Info, error) {
	letters, err := LogicalDriveLetters()
	if err != nil {
		return nil, err
	}

	var result []*Info
	for _, l := range letters {
		info, err := New(l)
		if err != nil {
			continue
		}
		if w.filter != nil && !w.filter(info) {
			continue
		}
		w.known[info.key()] = info
		result = append(result, info)
	}
	return result, nil
}

// Watch takes a baseline snapshot, then polls for changes.
// Returns a channel that receives Added and Removed events.
// The channel is closed when the context is cancelled.
//
// pollInterval controls how often changes are checked (default 500ms if 0).
func (w *Watcher) Watch(pollInterval time.Duration) (<-chan Event, error) {
	// Take initial snapshot to establish the baseline.
	if _, err := w.Snapshot(); err != nil {
		return nil, err
	}

	if pollInterval <= 0 {
		pollInterval = 500 * time.Millisecond
	}

	ch := make(chan Event)
	go w.pollLoop(ch, pollInterval)
	return ch, nil
}

func (w *Watcher) pollLoop(ch chan<- Event, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	defer close(ch)

	prevMask, _ := logicalDrivesMask()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			mask, err := logicalDrivesMask()
			if err != nil {
				ch <- Event{Err: err}
				continue
			}
			if mask == prevMask {
				continue
			}
			prevMask = mask

			w.detectChanges(ch)
		}
	}
}

func (w *Watcher) detectChanges(ch chan<- Event) {
	// Enumerate current drives.
	letters, err := LogicalDriveLetters()
	if err != nil {
		ch <- Event{Err: err}
		return
	}

	current := make(map[string]*Info)
	for _, l := range letters {
		info, err := New(l)
		if err != nil {
			continue
		}
		if w.filter != nil && !w.filter(info) {
			continue
		}
		current[info.key()] = info
	}

	// Detect additions.
	for key, info := range current {
		if _, exists := w.known[key]; !exists {
			ch <- Event{Kind: EventAdded, Drive: info}
		}
	}

	// Detect removals.
	for key, info := range w.known {
		if _, exists := current[key]; !exists {
			ch <- Event{Kind: EventRemoved, Drive: info}
		}
	}

	w.known = current
}

// key returns a stable identifier for deduplication.
// Prefers GUID; falls back to letter if GUID is unavailable.
func (d *Info) key() string {
	if d.GUID != "" {
		return d.GUID
	}
	return d.Letter
}
