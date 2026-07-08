# Build Instructions

## Prerequisites

1. Download **[llvm-mingw](https://github.com/mstorsjo/llvm-mingw)** from the repository.
2. Add the `bin` directory to your system's PATH environment variable (e.g., `C:\llvm-mingw-xxxxxxx\bin`).

## Preparation

Before building, ensure you have the necessary patcher binaries in `bins`
- `drvloader` is available [here](http://github.com/SouNobbao/drvloader-fork/releases/latest)
- `kvc` is available [here](https://github.com/wesmar/kvc/releases/tag/latest)
- `dse_elevator.exe` is compiled from `elevator.cpp`

## Compiling

1. Create a `build` directory in the project root.
2. Run the following compilation command:

> [!NOTE]
> Use the `-D_STABLE` flag to build with **drvloader**. If omitted, it will build with **KVC**.

```bash
clang++ --target=x86_64-w64-mingw32 -Oz -D_STABLE -Wno-deprecated -mwindows -municode -shared -static \
    -Iminhook/include -I. \
    -ffunction-sections -fdata-sections -fvisibility=hidden -fno-unwind-tables -fno-asynchronous-unwind-tables \
    -fno-exceptions -fno-rtti -flto=thin \
    config.cpp checks.cpp dllmain.cpp events.cpp injector.cpp patcher.cpp log.cpp watchdog.cpp afterburner.cpp hide_module.cpp \
    minhook/src/buffer.c minhook/src/hook.c minhook/src/trampoline.c minhook/src/hde/hde64.c minhook/src/hde/hde32.c \
    c_std/vector/vector.c c_std/string/std_string.c \
    -fuse-ld=lld -Wl,--gc-sections -Wl,--icf=all -Wl,--as-needed \
    -lshlwapi \
    -o build/dse.dll
```

## Disclaimer 
The extras files are optional
if you wanna know where to get them

- pe_reader > [LIEF](https://github.com/lief-project/LIEF)
- steamclient_loader_x64.exe > [gbe_fork](https://github.com/Detanup01/gbe_fork/)
- hypervisor-launcher.exe > [hypervisor-launcher](https://git.denuvosanctuary.com/andreh/hypervisor-launcher/)
