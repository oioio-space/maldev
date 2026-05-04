// data_extras — exercises BeaconDataShort + BeaconDataLength end-to-end.
// The Go-side caller packs an Args buffer with AddShort(0x1234) +
// AddString("hi") (LE wire format → 2 + 4 + 3 = 9 bytes total). The BOF
// reads the buffer length before and after consuming the 2-byte short
// and ships the three observed values [len_before, short_value,
// len_after] back as three big-endian ints inside a format buffer
// (BeaconFormatInt is the CS-canonical BE writer). The Go-side test
// decodes them and asserts:
//   len_before  == 9
//   short_value == 0x1234   (proves DataShort reads LE 2 bytes)
//   len_after   == 7        (proves DataLength reflects the cursor advance)
//
// Build:
//   x86_64-w64-mingw32-gcc -c data_extras.c -o data_extras.o ^
//       -O2 -Wall -ffreestanding -fno-stack-protector

typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} datap;

typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} formatp;

__declspec(dllimport) void  BeaconDataParse(datap *parser, char *buffer, int size);
__declspec(dllimport) short BeaconDataShort(datap *parser);
__declspec(dllimport) int   BeaconDataLength(datap *parser);

__declspec(dllimport) void  BeaconFormatAlloc(formatp *format, int maxsz);
__declspec(dllimport) void  BeaconFormatInt(formatp *format, int val);
__declspec(dllimport) char *BeaconFormatToString(formatp *format, int *outsize);
__declspec(dllimport) void  BeaconFormatFree(formatp *format);
__declspec(dllimport) void  BeaconOutput(int type, char *data, int len);
__declspec(dllimport) void  BeaconPrintf(int type, const char *fmt, ...);

#define CALLBACK_OUTPUT 0x0

void go(char *args, int len) {
    datap parser = {0};
    BeaconDataParse(&parser, args, len);

    int   len_before = BeaconDataLength(&parser);
    short s          = BeaconDataShort(&parser);
    int   len_after  = BeaconDataLength(&parser);

    formatp f = {0};
    BeaconFormatAlloc(&f, 64);
    BeaconFormatInt(&f, len_before);
    BeaconFormatInt(&f, (int)s);
    BeaconFormatInt(&f, len_after);

    int sz = 0;
    char *buf = BeaconFormatToString(&f, &sz);
    if (buf != 0 && sz > 0) {
        BeaconOutput(CALLBACK_OUTPUT, buf, sz);
    }
    BeaconFormatFree(&f);

    BeaconPrintf(CALLBACK_OUTPUT, "data_extras done\n");
}
