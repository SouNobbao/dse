# Build Instructions

## Prerequisites

1. Download **[llvm-mingw](https://github.com/mstorsjo/llvm-mingw)** from the repository.
2. Add the `bin` directory to your system's PATH environment variable (e.g., `C:\llvm-mingw-xxxxxxx\bin`).

## Preparation

Before building, ensure you have the necessary patcher binaries dumped into C++ source files. 
You can dump these files using `xxd` (for example, its available under git-bash):
```bash
xxd -i binary > name_bin.cpp
```

### Naming Requirements
Ensure your binary array and variables are named correctly in the dumped file:
- `bin_patcher`: The hex binary array.
- `bin_patcher_len`: The size of the binary.
- `patcherEnablearg`: The "restore command" argument.
- `patcherDisablearg`: The "bypass command" argument.

## Compiling

1. Create a `build` directory in the project root.
2. Run the following compilation command:

> [!NOTE]
> Use the `-D_STABLE` flag to build with **drvloader**. If omitted, it will build with **KVC**.

```bash
clang++ --target=x86_64-w64-mingw32 -O3 -D_STABLE -Wno-deprecated -mwindows -municode -shared -static \
    -Iminhook/include \
    config.cpp checks.cpp dllmain.cpp events.cpp injector.cpp patcher.cpp log.cpp watchdog.cpp afterburner.cpp hide_module.cpp \
    minhook/src/buffer.c minhook/src/hook.c minhook/src/trampoline.c minhook/src/hde/hde64.c minhook/src/hde/hde32.c \
    -lshlwapi -luser32 -lkernel32 -ladvapi32 -lshell32 -lole32 -loleaut32 \
    -o build/dse.dll
```