# Building steps

1. Download [llvm-mingw](https://github.com/mstorsjo/llvm-mingw) from the repo
2. Add to your system path enviroment `C:\llvm-mingw-xxxxxxx\bin`
3. Create `build` folder
4. Run the following command

```
clang++ --target=x86_64-w64-mingw32 -O3 -mwindows -municode -shared -static -Iminhook/include config.cpp dllmain.cpp events.cpp injector.cpp kvc.cpp log.cpp watchdog.cpp minhook/src/buffer.c minhook/src/hook.c minhook/src/trampoline.c minhook/src/hde/hde64.c minhook/src/hde/hde32.c -lshlwapi -luser32 -lkernel32 -ladvapi32 -o build/dse.dll
```