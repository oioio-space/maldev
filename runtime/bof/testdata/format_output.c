// format_output — exercises the BeaconFormat family + BeaconOutput +
// the bare-form __imp_<func> resolver in one BOF. The BOF allocates a
// 256-byte format buffer, appends the literal "tag=" then a 4-byte
// big-endian int (the current PID, queried via the bare-form
// GetCurrentProcessId import that the loader resolves through
// bareImportSearchOrder), ships the formatted bytes to the output
// channel via BeaconOutput, frees the buffer, and emits a trailer
// marker via BeaconPrintf.
//
// Asserted on the Go side:
//   - The output buffer contains "tag=" followed by 4 bytes that decode
//     (big-endian, matching BeaconFormatInt's CS-canonical wire) to the
//     current process PID.
//   - The trailer "format_output done\n" is present (proves the BOF
//     reached the end of `go` without faulting).
//
// Build:
//   x86_64-w64-mingw32-gcc -c format_output.c -o format_output.o \
//       -O2 -Wall -ffreestanding -fno-stack-protector

typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} formatp;

__declspec(dllimport) void  BeaconFormatAlloc(formatp *format, int maxsz);
__declspec(dllimport) void  BeaconFormatAppend(formatp *format, char *src, int len);
__declspec(dllimport) void  BeaconFormatInt(formatp *format, int val);
__declspec(dllimport) char *BeaconFormatToString(formatp *format, int *outsize);
__declspec(dllimport) void  BeaconFormatFree(formatp *format);
__declspec(dllimport) void  BeaconOutput(int type, char *data, int len);
__declspec(dllimport) void  BeaconPrintf(int type, const char *fmt, ...);

// Bare-form import — no DLL prefix. Resolved via the loader's
// bareImportSearchOrder (kernel32 first → hit on the first lookup).
__declspec(dllimport) unsigned long GetCurrentProcessId(void);

#define CALLBACK_OUTPUT 0x0

void go(char *args, int len) {
    (void)args;
    (void)len;

    formatp f = {0};
    BeaconFormatAlloc(&f, 256);

    BeaconFormatAppend(&f, "tag=", 4);
    BeaconFormatInt(&f, (int)GetCurrentProcessId());

    int sz = 0;
    char *buf = BeaconFormatToString(&f, &sz);
    if (buf != 0 && sz > 0) {
        BeaconOutput(CALLBACK_OUTPUT, buf, sz);
    }

    BeaconFormatFree(&f);
    BeaconPrintf(CALLBACK_OUTPUT, "format_output done\n");
}
