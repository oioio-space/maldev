// Victim binary: deliberately vulnerable to DLL search-order hijack.
// Calls LoadLibraryA("hijackme.dll") with no path — Windows searches
// the application directory FIRST, so any non-admin user who can
// write to the victim's directory can hijack the load.
//
// Built in pure C (mingw, -nostdlib, kernel32-only) ON PURPOSE: the
// privesc-e2e chain spawns the payload thread from inside the
// hijacked DllMain. If victim were Go, the spawned thread would
// re-initialise Go's runtime in a process where Go is already
// running → TLS slot 0 collision + scheduler conflict. A C victim
// keeps the process Go-runtime-free, so a Go probe payload can
// initialise cleanly when the packer's Mode-8 stub creates the
// payload thread.
//
// Deployed at C:\Vulnerable\victim.exe under a SYSTEM-context
// scheduled task triggered by the orchestrator from a low-privilege
// shell. Writes one line per LoadLibrary outcome to
// C:\ProgramData\maldev-marker\victim.log so the test harness can
// diagnose failures (DLL not found vs. wrong arch vs. successful
// hijack).
//
// Build:
//   x86_64-w64-mingw32-gcc -nostdlib -e mainCRTStartup \
//       -o victim.exe victim.c -lkernel32

#include <windows.h>

// Win32 imports required: LoadLibraryA, ExitProcess, Sleep,
// CreateFileA, WriteFile, CloseHandle, CreateDirectoryA,
// GetLastError, GetCurrentProcessId.
// `-nostdlib -lkernel32` covers all of those.

#define LOG_DIR   "C:\\ProgramData\\maldev-marker"
#define LOG_FILE  "C:\\ProgramData\\maldev-marker\\victim.log"

// Tiny formatter — itoa + memcpy — avoids any libc dependency.
static int utoa(unsigned long v, char *dst) {
    char buf[24];
    int n = 0;
    if (v == 0) {
        dst[0] = '0';
        return 1;
    }
    while (v > 0 && n < (int)sizeof(buf)) {
        buf[n++] = (char)('0' + (v % 10));
        v /= 10;
    }
    for (int i = 0; i < n; i++) {
        dst[i] = buf[n - 1 - i];
    }
    return n;
}

static int strlen_(const char *s) {
    int n = 0;
    while (s[n]) n++;
    return n;
}

// Appends one line to victim.log. Format-light by design — the test
// harness greps fixed prefixes ("LoadLibrary succeeded", etc.) and
// doesn't need timestamps the way the Go version emitted.
static void log_line(const char *prefix, DWORD numeric_suffix) {
    CreateDirectoryA(LOG_DIR, NULL); // no-op if already exists

    HANDLE h = CreateFileA(LOG_FILE, FILE_APPEND_DATA, FILE_SHARE_READ,
                           NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;

    char line[256];
    int off = 0;
    int n = strlen_(prefix);
    if (n > (int)sizeof(line) - 32) n = (int)sizeof(line) - 32;
    for (int i = 0; i < n; i++) line[off++] = prefix[i];
    line[off++] = ' ';
    off += utoa((unsigned long)numeric_suffix, line + off);
    line[off++] = '\r';
    line[off++] = '\n';

    DWORD written = 0;
    WriteFile(h, line, off, &written, NULL);
    CloseHandle(h);
}

// mainCRTStartup is the linker's expected entry when -nostdlib is
// in effect on mingw-w64. ExitProcess is required because there's
// no CRT cleanup to fall back on.
void mainCRTStartup(void) {
    log_line("victim start pid=", GetCurrentProcessId());

    HMODULE h = LoadLibraryA("hijackme.dll");
    if (h == NULL) {
        log_line("LoadLibrary failed err=", GetLastError());
        ExitProcess(0);
    }

    log_line("LoadLibrary succeeded handle=", (DWORD)(DWORD_PTR)h);

    // Race-avoidance window for Mode-8 (ConvertEXEtoDLL) chains.
    // The packed DllMain returns immediately after spawning the
    // payload thread; without this sleep, victim falls off the end
    // of main() and calls ExitProcess before the spawned thread
    // reaches its final WriteFile(whoami.txt). Real-world legitimate-
    // victim sideload chains (services, scheduled tasks) have
    // similarly long-lived hosts, so the sleep is faithful behaviour.
    // Slice 9.8.a — see docs/refactor-2026-doc/packer-actions-2026-05-12.md.
    log_line("sleeping ms=", 5000);
    Sleep(5000);
    log_line("victim exit pid=", GetCurrentProcessId());

    ExitProcess(0);
}
