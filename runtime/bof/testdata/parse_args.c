// parse_args — exercises the Beacon data-parsing API. Reads
// (int32, length-prefixed string) from the args buffer and prints
// them via BeaconPrintf.
//
// Caller-side packing (Go):
//   args := bof.NewArgs()
//   args.AddInt(42)
//   args.AddString("hello")
//   data := args.Pack()
//
// Build:
//   x86_64-w64-mingw32-gcc -c parse_args.c -o parse_args.o \
//       -O2 -Wall -ffreestanding -fno-stack-protector

typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} datap;

__declspec(dllimport) void  BeaconDataParse(datap *parser, char *buffer, int size);
__declspec(dllimport) int   BeaconDataInt(datap *parser);
__declspec(dllimport) char *BeaconDataExtract(datap *parser, int *out_len);
__declspec(dllimport) void  BeaconPrintf(int type, const char *fmt, ...);

#define CALLBACK_OUTPUT 0x0

void go(char *args, int len) {
    datap parser = {0};
    BeaconDataParse(&parser, args, len);

    int n = BeaconDataInt(&parser);
    int s_len = 0;
    char *s = BeaconDataExtract(&parser, &s_len);

    BeaconPrintf(CALLBACK_OUTPUT, "parsed args:\n");
    // BeaconPrintf forwards format string verbatim (no varargs
    // expansion); we feed the string raw.
    if (s != 0 && s_len > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, s);
        BeaconPrintf(CALLBACK_OUTPUT, "\n");
    }
    (void)n; // n captured but not printed (no %d expansion yet).
}
