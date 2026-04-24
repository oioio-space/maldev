/*
 * canary.c — minimal DLL for dllhijack.Validate().
 *
 * On DLL_PROCESS_ATTACH, writes a marker file whose name matches the
 * default Validate() glob ("maldev-canary-*.marker") into %ProgramData%,
 * containing the victim PID, a nanosecond timestamp, and the canary's
 * own file path. Returns TRUE so the victim's LoadLibrary succeeds.
 *
 * The victim may subsequently call an undefined export from this DLL
 * and crash — that's fine; by then the marker has already been written.
 *
 * Build (MinGW on Linux):
 *   x86_64-w64-mingw32-gcc -shared -s -O2 canary.c -o canary.dll \
 *       -Wl,--subsystem,windows -lkernel32
 *
 * Build (MSVC on Windows):
 *   cl /LD /O2 canary.c /link /SUBSYSTEM:WINDOWS kernel32.lib
 *
 * Size target: ~10 KB. Larger is fine; we embed nothing here so it's
 * up to the operator to trim.
 */

#include <windows.h>
#include <stdio.h>

static void write_marker(HMODULE self) {
    CHAR programData[MAX_PATH];
    DWORD n = GetEnvironmentVariableA("ProgramData", programData, sizeof(programData));
    if (n == 0 || n >= sizeof(programData)) {
        strcpy_s(programData, sizeof(programData), "C:\\ProgramData");
    }

    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    DWORD pid = GetCurrentProcessId();

    CHAR markerPath[MAX_PATH];
    _snprintf_s(markerPath, sizeof(markerPath), _TRUNCATE,
        "%s\\maldev-canary-%lu-%lld.marker", programData, pid, now.QuadPart);

    HANDLE h = CreateFileA(markerPath, GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        return;
    }

    CHAR selfPath[MAX_PATH] = {0};
    GetModuleFileNameA(self, selfPath, sizeof(selfPath));

    CHAR body[MAX_PATH * 2];
    int len = _snprintf_s(body, sizeof(body), _TRUNCATE,
        "pid=%lu qpc=%lld canary=%s\r\n", pid, now.QuadPart, selfPath);

    DWORD written = 0;
    WriteFile(h, body, (DWORD)len, &written, NULL);
    CloseHandle(h);
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        write_marker(hinst);
    }
    return TRUE;
}
