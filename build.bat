@echo off

echo [*] Configuring CMake project...
cmake -B build -G "MinGW Makefiles" -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Release || (
    echo [!] CMake configuration failed.
    exit /b 1
)

echo [*] Compiling dse.dll ...
cmake --build build -j
if %ERRORLEVEL% neq 0 (
    echo [!] Build failed.
    exit /b %ERRORLEVEL%
)

echo [*] Build completed successfully.

