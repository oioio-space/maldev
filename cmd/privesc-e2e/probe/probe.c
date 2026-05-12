/* Privesc-E2E whoami probe (simplified after debug 9.6.d).
 *
 * mingw -nostdlib EXE that:
 *   1. Writes a breadcrumb to C:\probe-root-marker.txt (FIRST)
 *   2. Calls advapi32!GetUserNameA via LoadLibrary + GetProcAddress
 *      (avoids needing -ladvapi32 import while still working in
 *      SYSTEM-spawned-thread context)
 *   3. Writes "<user>|pid=<pid>\n" to
 *      C:\ProgramData\maldev-marker\whoami.txt
 *   4. Sleep INFINITE
 *
 * Why dynamic resolve of GetUserNameA: linking advapi32 statically
 * adds an import-table entry that the Mode-8 stub may not resolve
 * cleanly in the SYSTEM-context thread. LoadLibraryA is in the IAT
 * via kernel32 already; resolving advapi32 at runtime sidesteps
 * any IAT-vs-stub-disagreement.
 *
 * Build: x86_64-w64-mingw32-gcc -nostdlib -e main -o probe.exe \
 *          probe.c -lkernel32
 */
#include <windows.h>

void __main(void) {}

typedef BOOL (WINAPI *GetUserNameA_t)(LPSTR, LPDWORD);

static const wchar_t kRootMarker[]  = L"C:\\probe-root-marker.txt";
static const wchar_t kStartedPath[] = L"C:\\ProgramData\\maldev-marker\\probe-started.txt";
static const wchar_t kMarkerPath[]  = L"C:\\ProgramData\\maldev-marker\\whoami.txt";

static void writeFile(const wchar_t *path, const char *bytes, DWORD nbytes) {
    HANDLE h = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD written;
    WriteFile(h, bytes, nbytes, &written, NULL);
    FlushFileBuffers(h);
    CloseHandle(h);
}

static int u32ToStr(DWORD v, char *buf) {
    char tmp[12]; int n = 0;
    if (v == 0) { buf[0] = '0'; return 1; }
    while (v > 0 && n < 11) { tmp[n++] = '0' + (v % 10); v /= 10; }
    for (int i = 0; i < n; i++) buf[i] = tmp[n - 1 - i];
    return n;
}

int main(void) {
    /* Breadcrumb 1: just-reached-main, in C:\ root (writable in
     * SYSTEM context, visible cross-process via FILE_SHARE_READ). */
    writeFile(kRootMarker, "main\n", 5);

    /* Breadcrumb 2: in our marker dir. If this exists but
     * whoami.txt doesn't, the dir was reachable but the actual
     * marker write later failed. */
    writeFile(kStartedPath, "started\n", 8);

    /* Resolve GetUserNameA dynamically. advapi32 may not be loaded
     * yet -- pull it in. */
    HMODULE adv = LoadLibraryA("advapi32.dll");
    char line[512];
    int n = 0;
    if (adv) {
        GetUserNameA_t pGetUserNameA = (GetUserNameA_t)GetProcAddress(adv, "GetUserNameA");
        if (pGetUserNameA) {
            char name[256] = {0};
            DWORD nameLen = 256;
            if (pGetUserNameA(name, &nameLen)) {
                /* nameLen includes the trailing NUL; strip it. */
                int copy = (int)nameLen - 1;
                if (copy < 0) copy = 0;
                if (copy > 255) copy = 255;
                for (int i = 0; i < copy; i++) line[n++] = name[i];
            }
        }
    }
    if (n == 0) {
        /* Fallback: identify ourselves with at least the PID so
         * the marker is non-empty and the chain is provable. */
        const char fb[] = "<no-getusername>";
        for (int i = 0; fb[i]; i++) line[n++] = fb[i];
    }
    line[n++] = '|'; line[n++] = 'p'; line[n++] = 'i'; line[n++] = 'd'; line[n++] = '=';
    n += u32ToStr(GetCurrentProcessId(), line + n);
    line[n++] = '\n';

    writeFile(kMarkerPath, line, n);

    Sleep(200);
    Sleep(INFINITE);
    return 0;
}
