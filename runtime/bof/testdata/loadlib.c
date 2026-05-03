// loadlib — exercises the Win32 dollar-import resolver path.
// Imports kernel32!LoadLibraryA and kernel32!FreeLibrary via
// the CS-format __imp_<DLL>$<Func> convention. The Go-side
// resolver translates these to addresses via PEB walk + ROR13
// export-table match — no GetProcAddress / LoadLibrary import
// in the BOF's COFF symbol table beyond the dollar-import names
// themselves.
//
// Build:
//   x86_64-w64-mingw32-gcc -c loadlib.c -o loadlib.o \
//       -O2 -Wall -ffreestanding -fno-stack-protector

typedef void *HMODULE;
typedef int   BOOL;

__declspec(dllimport) HMODULE LoadLibraryA(const char *lpLibFileName);
__declspec(dllimport) BOOL    FreeLibrary(HMODULE hLibModule);
__declspec(dllimport) void    BeaconPrintf(int type, const char *fmt, ...);

#define CALLBACK_OUTPUT 0x0

void go(char *args, int len) {
    (void)args;
    (void)len;

    HMODULE h = LoadLibraryA("crypt32.dll");
    if (h != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "crypt32.dll loaded\n");
        FreeLibrary(h);
        BeaconPrintf(CALLBACK_OUTPUT, "crypt32.dll unloaded\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "LoadLibraryA(crypt32.dll) returned NULL\n");
    }
}
