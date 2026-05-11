/* Slice-4 DLL packing fixture. Mingw -nostdlib so no TLS callbacks
 * (matches the winhello_w32.exe pattern). Exports `add`,
 * `call_via_fp`, plus a no-op `DllMain`. Designed so that:
 *   1. PackBinary on the unmodified DLL produces a packed copy,
 *   2. LoadLibrary loads the packed output,
 *   3. GetProcAddress("add") + add(7, 35) returns 42,
 *   4. GetProcAddress("call_via_fp") + call_via_fp(7, 35) returns
 *      42 — exercises the relocated function-pointer storage
 *      after the loader rebased the BASERELOC table.
 *
 * **Toolchain limitation, 2026-05-11:** mingw `ld` for x86_64 PE
 * refuses to emit a `.reloc` section even with --enable-reloc-section
 * + --dynamicbase. Empirically tested with mingw-w64 (Fedora 44).
 * Until that's worked around, the build target `make testlib` here
 * produces a *.reloc-less* DLL that InjectStubDLL refuses with
 * ErrNoExistingRelocDir. To exercise the full pack pipeline:
 *   - Either rebuild with MSVC on the Win VM
 *     (`cl /LD testlib.c /link /DYNAMICBASE`), or
 *   - Run the in-memory synthetic-fixture test
 *     (TestPackBinary_FormatWindowsDLL_HappyPath) which uses
 *     transform's BuildMinimalPE32Plus + manual reloc append.
 *
 * The committed pack-time test (packer_dll_test.go) covers the byte
 * pipeline; the LoadLibrary roundtrip needs an MSVC-built fixture.
 * `testlib.dll` is gitignored — rebuild locally if needed. */
#include <windows.h>

/* The mingw linker injects this on -nostdlib DLLs; provide a no-op. */
BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved) {
    (void)hInst;
    (void)reason;
    (void)reserved;
    return TRUE;
}

__declspec(dllexport) int add(int a, int b) {
    return a + b;
}

/* Global function-pointer variable. Its initial value (the absolute
 * VA of `add`) is only known after image-base relocation, so the
 * mingw linker emits a DIR64 entry in the BASERELOC table covering
 * the storage of `fp`. Without at least one such absolute reference,
 * mingw -shared -O2 drops the .reloc section entirely and
 * InjectStubDLL refuses the fixture with ErrNoExistingRelocDir.
 *
 * The Win VM E2E also calls call_via_fp() as a second-export sanity
 * check that the rebased pointer survived packing (the test rejects
 * GetProcAddress returning NULL — different failure path from
 * call-through-IAT). */
static int (*const fp)(int, int) = add;
__declspec(dllexport) int call_via_fp(int a, int b) { return fp(a, b); }
