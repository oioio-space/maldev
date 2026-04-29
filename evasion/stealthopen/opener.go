package stealthopen

import (
	"io"
	"os"
)

// Opener abstracts the "open a file for reading" step used across the
// library. It mirrors how *wsyscall.Caller is passed as an optional
// parameter for syscall routing: packages that read files (unhook,
// phantomdll, herpaderping, timestomp, ...) accept an Opener as an
// optional field; nil means "use the default path-based open", non-nil
// routes through whatever stealth strategy the caller configured.
//
// The intended strategies are:
//
//   - Standard (this package): plain os.Open(path). Default when no Opener
//     is provided. Path-based EDR file hooks see the real path.
//   - Stealth (windows only): OpenByID via the file's NTFS Object ID. Path
//     filters on CreateFile / NtCreateFile never see the target path —
//     only the volume root handle.
//
// Implementations are free to add caching, logging, or per-call policy.
// The contract is intentionally narrow: take a path, return an open
// *os.File (caller must Close) or an error.
type Opener interface {
	Open(path string) (*os.File, error)
}

// Standard is the default Opener. It delegates to os.Open, so path-based
// EDR hooks observe the real path. Use it explicitly when a nil fallback
// is inconvenient or when you want to make the default choice obvious at
// the call site.
type Standard struct{}

// Open implements Opener.
func (*Standard) Open(path string) (*os.File, error) { return os.Open(path) }

// Use returns opener if non-nil, otherwise a zero-value *Standard. This
// is the helper consuming packages call to normalize the optional param.
func Use(opener Opener) Opener {
	if opener != nil {
		return opener
	}
	return &Standard{}
}

// OpenRead opens path through Use(opener) and returns the full contents.
// Shared helper for callers that want the old os.ReadFile shape while
// still benefiting from a stealth strategy when opener is non-nil. The
// file is always closed before returning.
func OpenRead(opener Opener, path string) ([]byte, error) {
	f, err := Use(opener).Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// Creator is the write-side parallel of [Opener]: a narrow contract
// for "create or truncate a file at path for writing". Implementations
// can layer transactional NTFS, alternate data streams, encrypted
// streams, or any operator-controlled write primitive on top of the
// raw os.Create — same composition story as [Opener] for read paths.
type Creator interface {
	Create(path string) (io.WriteCloser, error)
}

// StandardCreator is the default Creator. It delegates to os.Create —
// the resulting *os.File satisfies io.WriteCloser. Use it explicitly
// when a nil fallback is inconvenient at the call site.
type StandardCreator struct{}

// Create implements Creator.
func (*StandardCreator) Create(path string) (io.WriteCloser, error) { return os.Create(path) }

// UseCreator returns creator if non-nil, otherwise a zero-value
// *StandardCreator. Mirrors [Use] for the write side.
func UseCreator(creator Creator) Creator {
	if creator != nil {
		return creator
	}
	return &StandardCreator{}
}
