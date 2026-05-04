// error_spawnto — exercises BeaconErrorD (errors-channel routing) and
// BeaconGetSpawnTo (round-trip of the operator-configured spawn-to
// path). The BOF emits a synthetic error tagged (type=7, data=42),
// asks the loader for the spawn-to path, and echoes it back through
// BeaconPrintf so the Go-side test sees both the output and the
// errors buffer populated.
//
// Asserted on the Go side:
//   - (*BOF).Errors() returns "error type=7 data=42\n" — proves the
//     BeaconErrorD callback routes to the per-BOF errors buffer
//     instead of the output buffer.
//   - The output buffer contains "spawn-to=<path>\n" matching the
//     SetSpawnTo("notepad.exe") configured before Execute — proves the
//     SetSpawnTo / GetSpawnTo round-trip via the pinned spawnToCStr.
//
// Build:
//   x86_64-w64-mingw32-gcc -c error_spawnto.c -o error_spawnto.o \
//       -O2 -Wall -ffreestanding -fno-stack-protector

__declspec(dllimport) void  BeaconErrorD(int type, int data);
__declspec(dllimport) char *BeaconGetSpawnTo(void);
__declspec(dllimport) void  BeaconPrintf(int type, const char *fmt, ...);

#define CALLBACK_OUTPUT 0x0

void go(char *args, int len) {
    (void)args;
    (void)len;

    BeaconErrorD(7, 42);

    char *st = BeaconGetSpawnTo();
    if (st != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "spawn-to=");
        BeaconPrintf(CALLBACK_OUTPUT, st);
        BeaconPrintf(CALLBACK_OUTPUT, "\n");
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "spawn-to=NULL\n");
    }
}
