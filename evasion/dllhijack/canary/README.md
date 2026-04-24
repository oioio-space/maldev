# canary.dll — reference canary for `dllhijack.Validate`

`canary.c` is a 30-line minimal DLL that, on `DLL_PROCESS_ATTACH`,
writes a file matching the default glob expected by
`dllhijack.Validate`:

```
%ProgramData%\maldev-canary-<PID>-<QPC>.marker
```

File contents:

```
pid=<N> qpc=<N> canary=<self path>\r\n
```

## Building

### MinGW cross-compile from Linux (recommended — reproducible)

```bash
sudo dnf install -y mingw64-gcc   # Fedora
sudo apt install -y gcc-mingw-w64-x86-64   # Debian/Ubuntu

x86_64-w64-mingw32-gcc -shared -s -O2 canary.c -o canary.dll \
    -Wl,--subsystem,windows -lkernel32
```

### MSVC on Windows

```cmd
cl /LD /O2 canary.c /link /SUBSYSTEM:WINDOWS kernel32.lib
```

The resulting `canary.dll` (~10 KB) is the `canaryDLL []byte` argument
to `dllhijack.Validate`:

```go
bytes, _ := os.ReadFile("canary.dll")
result, err := dllhijack.Validate(opp, bytes, dllhijack.ValidateOpts{})
if err != nil { log.Fatal(err) }
fmt.Printf("confirmed=%v marker=%s\n", result.Confirmed, result.MarkerPath)
```

## Why this is not shipped pre-built

A pre-built `canary.dll` committed to the repo would pin a specific
toolchain + optimization level, and every scan tool would then flag a
known-signature artifact. Shipping only the source lets each operator
produce a canary whose PE hash is unique.

Operators who want a one-time artifact for reuse can commit their own
build into a private fork.
