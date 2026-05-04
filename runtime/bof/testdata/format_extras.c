// format_extras — exercises the remaining Beacon API stubs not covered
// by the other example BOFs:
//
//   BeaconFormatReset    rewinds the format-buffer cursor to position 0.
//   BeaconFormatPrintf   verbatim format-string append (no varargs
//                        expansion — same contract as BeaconPrintf).
//   BeaconErrorDD        writes "error type=<t> data1=<a> data2=<b>" to
//                        the per-BOF errors channel.
//   BeaconErrorNA        writes "error type=<t>" to the same channel.
//
// Sequence:
//   1. BeaconErrorDD(3, 11, 22)         — populates errors channel.
//   2. BeaconErrorNA(5)                 — populates errors channel again.
//   3. FormatPrintf("first")            — 5 bytes appended.
//   4. FormatReset                      — cursor returns to 0; the
//                                         underlying bytes are not zeroed
//                                         but length=0 means the next
//                                         ToString sees an empty buffer.
//   5. FormatPrintf("after-reset")      — 11 bytes overwrite "first" and
//                                         extend past it.
//   6. BeaconOutput(buf, sz)            — ships the 11 bytes ("after-reset").
//   7. BeaconPrintf("format_extras done\n")
//
// Asserted on the Go side:
//   - Output starts with "after-reset"   (proves Reset + 2nd Printf).
//   - Output does NOT contain "first"   (proves Reset's effect is not
//                                        leaked through ToString sizing).
//   - Output contains "format_extras done"
//   - (*BOF).Errors() contains both
//       "error type=3 data1=11 data2=22"
//       "error type=5"
//
// Build:
//   x86_64-w64-mingw32-gcc -c format_extras.c -o format_extras.o ^
//       -O2 -Wall -ffreestanding -fno-stack-protector

typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} formatp;

__declspec(dllimport) void  BeaconFormatAlloc(formatp *format, int maxsz);
__declspec(dllimport) void  BeaconFormatReset(formatp *format);
__declspec(dllimport) void  BeaconFormatPrintf(formatp *format, char *fmt, ...);
__declspec(dllimport) char *BeaconFormatToString(formatp *format, int *outsize);
__declspec(dllimport) void  BeaconFormatFree(formatp *format);
__declspec(dllimport) void  BeaconOutput(int type, char *data, int len);
__declspec(dllimport) void  BeaconErrorDD(int type, int data1, int data2);
__declspec(dllimport) void  BeaconErrorNA(int type);
__declspec(dllimport) void  BeaconPrintf(int type, const char *fmt, ...);

#define CALLBACK_OUTPUT 0x0

void go(char *args, int len) {
    (void)args;
    (void)len;

    BeaconErrorDD(3, 11, 22);
    BeaconErrorNA(5);

    formatp f = {0};
    BeaconFormatAlloc(&f, 64);

    BeaconFormatPrintf(&f, "first");
    BeaconFormatReset(&f);
    BeaconFormatPrintf(&f, "after-reset");

    int sz = 0;
    char *buf = BeaconFormatToString(&f, &sz);
    if (buf != 0 && sz > 0) {
        BeaconOutput(CALLBACK_OUTPUT, buf, sz);
    }
    BeaconFormatFree(&f);

    BeaconPrintf(CALLBACK_OUTPUT, "format_extras done\n");
}
