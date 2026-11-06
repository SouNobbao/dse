# Build Instructions

## Prerequisites

1. Download **[llvm-mingw](https://github.com/mstorsjo/llvm-mingw)** from the repository.
2. Add the `bin` directory to your system's PATH environment variable (e.g., `C:\llvm-mingw-xxxxxxx\bin`).

## Preparation

Before building, ensure you have `dse_elevator.exe` (compiled from `elevator.cpp`) in `bins/`.

## Compiling

1. Create a `build` directory in the project root.
2. Run CMake:

```bash
cmake -B build -G "MinGW Makefiles"
cmake --build build -j
```

## Disclaimer 
The extras files are optional
if you wanna know where to get them

- pe_reader > [LIEF](https://github.com/lief-project/LIEF)
- steamclient_loader_x64.exe > [gbe_fork](https://github.com/Detanup01/gbe_fork/)
- hypervisor-launcher.exe > [hypervisor-launcher](https://git.denuvosanctuary.com/andreh/hypervisor-launcher/)
