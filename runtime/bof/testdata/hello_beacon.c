// hello_beacon — smallest BOF that exercises the Beacon API stub
// table. Imports __imp_BeaconPrintf and prints a greeting plus the
// first byte of the args buffer.
//
// Build:
//   x86_64-w64-mingw32-gcc -c hello_beacon.c -o hello_beacon.o \
//       -O2 -Wall -ffreestanding -fno-stack-protector

// CS BOF declarations — the loader patches __imp_BeaconPrintf at
// relocation time.
__declspec(dllimport) void BeaconPrintf(int type, const char *fmt, ...);

#define CALLBACK_OUTPUT 0x0

void go(char *args, int len) {
    BeaconPrintf(CALLBACK_OUTPUT, "hello from BOF\n");
    if (len > 0 && args != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "first arg byte: ");
        // Direct byte print — no varargs (the Go-side stub forwards
        // the format string verbatim and does not expand %d).
        char one[2];
        one[0] = args[0];
        one[1] = 0;
        BeaconPrintf(CALLBACK_OUTPUT, one);
    }
}
