/* Privesc-E2E whoami probe.
 *
 * mingw -nostdlib EXE that:
 *   1. Opens a process token, asks for the username (kernel32+advapi32
 *      via GetUserNameW), writes it to C:\ProgramData\maldev-marker\whoami.txt
 *   2. Sleeps INFINITE so the spawned thread stays visible if the
 *      operator wants to dump it.
 *
 * Why C and not Go: when this EXE is packed via PackBinary{ConvertEXEtoDLL:true}
 * and the resulting DLL is LoadLibrary'd inside a non-Go host (here, our
 * SYSTEM-context victim.exe), the spawned thread starts at this binary's
 * OEP. Go's runtime requires being the process entry point — the thread-
 * spawn shape kills it instantly. -nostdlib C with explicit Win32 calls
 * has no such constraint.
 *
 * Build: x86_64-w64-mingw32-gcc -nostdlib -e mainCRTStartup -o probe.exe \
 *          probe.c -ladvapi32 -lkernel32
 */
#include <windows.h>

/* mingw -nostdlib's libgcc still pulls a __main symbol; stub it. */
void __main(void) {}

/* OpenProcessToken / GetTokenInformation / LookupAccountSidW are in
 * advapi32 too — same risk. Use kernel32 ONLY: read the SID directly
 * from the token via NtQueryInformationToken, format it. Works without
 * advapi32 import at all.
 *
 * Actually simpler: GetEnvironmentVariableW("USERNAME") is kernel32 and
 * SYSTEM has %USERNAME% = SYSTEM. */

static const wchar_t kMarkerPath[] = L"C:\\ProgramData\\maldev-marker\\whoami.txt";
static const wchar_t kStartedPath[] = L"C:\\ProgramData\\maldev-marker\\probe-started.txt";

static void writeFile(const wchar_t *path, const char *bytes, DWORD nbytes) {
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD written;
    WriteFile(h, bytes, nbytes, &written, NULL);
    CloseHandle(h);
}

/* Manual int -> ASCII for PID (no CRT). */
static int u32ToStr(DWORD v, char *buf) {
    char tmp[12]; int n = 0;
    if (v == 0) { buf[0] = '0'; return 1; }
    while (v > 0 && n < 11) { tmp[n++] = '0' + (v % 10); v /= 10; }
    for (int i = 0; i < n; i++) buf[i] = tmp[n - 1 - i];
    return n;
}

/* UTF-16 -> UTF-8 (ASCII subset only — usernames are ASCII in our test). */
static int wToA(const wchar_t *src, char *dst, int srcLen) {
    int n = 0;
    for (int i = 0; i < srcLen && src[i]; i++) {
        if (src[i] < 0x80) dst[n++] = (char)src[i];
        else dst[n++] = '?';
    }
    return n;
}

int main(void) {
    /* Brute-force breadcrumb to C:\ root — same path shape as the
     * known-working probe_converted.c. If this appears but
     * kStartedPath doesn't, ProgramData write is the issue. If THIS
     * doesn't appear, the spawned thread itself never reached main. */
    HANDLE root = CreateFileW(L"C:\\probe-root-marker.txt", GENERIC_WRITE,
                              0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (root != INVALID_HANDLE_VALUE) {
        DWORD w;
        WriteFile(root, "main reached\n", 13, &w, NULL);
        CloseHandle(root);
    }
    writeFile(kStartedPath, "started\n", 8);

    wchar_t name[256] = {0};
    DWORD nameLen = GetEnvironmentVariableW(L"USERNAME", name, 256);
    if (nameLen == 0) {
        /* fallback hint so we still see SOMETHING in the marker */
        const wchar_t fallback[] = L"<no-USERNAME-env>";
        for (int i = 0; fallback[i] && i < 255; i++) name[i] = fallback[i];
        nameLen = (DWORD)(sizeof(fallback)/sizeof(wchar_t)) - 1;
    }

    /* Build "<name>|pid=<pid>\n" in a fixed buffer. */
    char line[512];
    int n = wToA(name, line, (int)nameLen);
    line[n++] = '|';
    line[n++] = 'p'; line[n++] = 'i'; line[n++] = 'd'; line[n++] = '=';
    n += u32ToStr(GetCurrentProcessId(), line + n);
    line[n++] = '\n';

    writeFile(kMarkerPath, line, n);

    /* Keep the thread visible — same pattern as probe_converted.c. */
    Sleep(INFINITE);
    return 0;
}
