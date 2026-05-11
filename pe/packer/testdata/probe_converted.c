/* Slice-5.5.x EXE→DLL real-loader probe.
 *
 * A mingw -nostdlib EXE whose main() writes a marker byte to a
 * known path then Sleeps INFINITE. Packed via
 * `PackBinary(ConvertEXEtoDLL=true)` it becomes a DLL whose
 * DllMain decrypts .text + spawns CreateThread(OEP); the thread
 * runs THIS main() which produces the observable side effect the
 * E2E harness (TestPackBinary_ConvertEXEtoDLL_LoadLibrary_E2E)
 * checks.
 *
 * Build: `make probe_converted` (or x86_64-w64-mingw32-gcc with
 * the same flags as winhello_w32.exe — -nostdlib so no CRT TLS
 * callbacks, -e main so the linker uses main directly as the
 * entry point).
 *
 * Why Sleep INFINITE instead of return: when main() returns in a
 * -nostdlib EXE, BaseThreadInitThunk catches the return and calls
 * ExitThread — kills only this thread, not the host process. But
 * the harness Sleeps 2 s then reads the marker; if main() exited
 * early the thread is gone but the marker file is still there, so
 * the test still passes. Sleep INFINITE is belt-and-suspenders:
 * keeps the thread visible if a diagnostic harness wants to dump
 * thread state.
 *
 * Marker path is C:\maldev-probe-marker.txt — writable by any
 * user with C:\ root write access (Admin on default Win10). The
 * E2E harness ensures the file is deleted before LoadLibrary so
 * a stale marker from a previous run doesn't false-positive the
 * assertion.
 */
#include <windows.h>

/* mingw -nostdlib stubs the constructor it injects; we have no
 * globals so the no-op definition keeps the linker happy. */
void __main(void) {}

int main(void) {
    HANDLE h = CreateFileA(
        "C:\\maldev-probe-marker.txt",
        GENERIC_WRITE,
        0,                    /* dwShareMode = exclusive write */
        NULL,                 /* lpSecurityAttributes */
        CREATE_ALWAYS,        /* overwrites any stale marker */
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD written;
        /* "OK\n" — three bytes, distinguishable from zero-fill. */
        WriteFile(h, "OK\n", 3, &written, NULL);
        CloseHandle(h);
    }
    /* Keep the thread alive — see file-header comment. */
    Sleep(INFINITE);
    return 0;
}
