/* Phase 2-F-3-c-3 fixture: a non-Go Windows binary that
 * `PlanPE` accepts (no TLS callbacks). Built via mingw with
 * -nostdlib so the C runtime's TLS init thunks aren't linked
 * in. Calls Win32 directly — no `puts`, no globals, no
 * constructors.
 *
 * Used to verify the packer's coverage of "non-Go" payloads
 * that are still small / no-CRT. Default mingw output (with
 * CRT) gets rejected with `transform.ErrTLSCallbacks`.
 *
 * Build target in testdata/Makefile: `winhello_w32`.
 */
#include <windows.h>

/* Stub the constructor mingw injects — we have no globals so
 * we don't need its work, and not having it lets the linker
 * succeed under -nostdlib. */
void __main(void) {}

void main(void) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD w;
    WriteFile(h, "hello from w32\n", 15, &w, NULL);
    ExitProcess(0);
}
