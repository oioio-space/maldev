package dllhijack

import "strings"

// pathEntry pairs a PATH directory with the source registry hive it
// came from. FromSystem true means the dir is in
// `HKLM\…\Session Manager\Environment\Path` — that's the one SYSTEM-
// context unqualified CreateProcess walks. User-hive dirs only apply
// when the SAME user launches a process unqualified, so they offer
// no integrity gain.
type pathEntry struct {
	Dir        string
	FromSystem bool
}

// splitPath chops a Windows-style %PATH% (";"-separated) into
// trimmed, non-empty directory strings. Pure function; tested
// cross-platform.
func splitPath(raw string) []string {
	var out []string
	for _, p := range strings.Split(raw, ";") {
		// Strip whitespace and quoting added by some installers.
		p = strings.TrimSpace(p)
		p = strings.Trim(p, `"`)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

// mergePathSources de-duplicates entries (case-insensitive on Windows
// path comparison) across the system + user hives while preserving
// the system-first order — that's the order SYSTEM-context processes
// observe. Same dir present in both hives is kept once with
// FromSystem=true (the strongest signal for the hijack scoring).
func mergePathSources(systemRaw, userRaw string) []pathEntry {
	sys := splitPath(systemRaw)
	usr := splitPath(userRaw)
	out := make([]pathEntry, 0, len(sys)+len(usr))
	seen := make(map[string]struct{}, len(sys)+len(usr))
	for _, d := range sys {
		k := strings.ToLower(d)
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, pathEntry{Dir: d, FromSystem: true})
	}
	for _, d := range usr {
		k := strings.ToLower(d)
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, pathEntry{Dir: d, FromSystem: false})
	}
	return out
}
