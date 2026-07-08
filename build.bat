@echo off
echo [*] Checking for MSVC helper...
if exist setup_msvc.bat (
    echo [*] MSVC setup found — running setup_msvc.bat
    call setup_msvc.bat || (
        echo [!] setup_msvc.bat failed.
        exit /b 1
    )
    rem Backup original source files so we can restore placeholders later
    if exist elevator_bin.cpp copy /Y elevator_bin.cpp elevator_bin.cpp.bakmsvc >nul 2>&1
    if exist drvloader_bin.cpp copy /Y drvloader_bin.cpp drvloader_bin.cpp.bakmsvc >nul 2>&1
    if exist kvc_bin.cpp copy /Y kvc_bin.cpp kvc_bin.cpp.bakmsvc >nul 2>&1

    rem Produce binary hex replacements for elevator, drvloader, and kvc if present
    echo [*] Preparing binary embed replacements
    powershell -NoProfile -ExecutionPolicy Bypass -Command " $xxd = Get-Command xxd -ErrorAction SilentlyContinue; function Get-Hex([string]$path){ if ($xxd){ $i = & xxd -i $path | Out-String; $m = [regex]::Match($i,'\{([\s\S]*)\}\s*;'); if ($m.Success){ return $m.Groups[1].Value } else { throw 'xxd output parse failed' } } else { $b = [System.IO.File]::ReadAllBytes($path); return ($b | ForEach-Object { '0x' + $_.ToString('x2') }) -join ', ' } }; if (Test-Path '.\bins\dse_elevator.exe'){ $el = Get-Hex '.\bins\dse_elevator.exe'; $text = Get-Content '.\elevator_bin.cpp' -Raw; $text = $text -replace '%%placeholder_el_bin%%',$el; Set-Content '.\elevator_bin.cpp' -Value $text -Encoding ASCII }; if (Test-Path '.\bins\drvloader.exe'){ $drv = Get-Hex '.\bins\drvloader.exe'; $text = Get-Content '.\drvloader_bin.cpp' -Raw; $text = $text -replace '%%placeholder_drv_bin%%',$drv; Set-Content '.\drvloader_bin.cpp' -Value $text -Encoding ASCII }; if (Test-Path '.\bins\kvc.exe'){ $kvc = Get-Hex '.\bins\kvc.exe'; $text = Get-Content '.\kvc_bin.cpp' -Raw; $text = $text -replace '%%placeholder_kvc_bin%%',$kvc; Set-Content '.\kvc_bin.cpp' -Value $text -Encoding ASCII } " || ( echo [!] Failed to produce binary hex replacements. & exit /b 1 )

    echo [*] Configuring CMake (MSVC NMake)
    cmake -S . -B build-msvc -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release
    set ERR=%ERRORLEVEL%
    if not %ERR%==0 (
        echo [!] CMake configuration failed.
        goto :restore_and_exit
    )

    echo [*] Building (MSVC)
    cmake --build build-msvc --config Release
    set ERR=%ERRORLEVEL%
    if not %ERR%==0 (
        echo [!] Build failed.
        goto :restore_and_exit
    )

    set ERR=0
    goto :restore_and_continue
)

echo [*] Configuring CMake project (MinGW)...
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

:restore_and_exit
echo [*] Restoring source placeholders (error)
if exist elevator_bin.cpp.bakmsvc copy /Y elevator_bin.cpp.bakmsvc elevator_bin.cpp >nul 2>&1
if exist drvloader_bin.cpp.bakmsvc copy /Y drvloader_bin.cpp.bakmsvc drvloader_bin.cpp >nul 2>&1
if exist kvc_bin.cpp.bakmsvc copy /Y kvc_bin.cpp.bakmsvc kvc_bin.cpp >nul 2>&1
del /q elevator_bin.cpp.bakmsvc drvloader_bin.cpp.bakmsvc kvc_bin.cpp.bakmsvc >nul 2>&1
exit /b %ERR%

:restore_and_continue
echo [*] Restoring source placeholders
if exist elevator_bin.cpp.bakmsvc copy /Y elevator_bin.cpp.bakmsvc elevator_bin.cpp >nul 2>&1
if exist drvloader_bin.cpp.bakmsvc copy /Y drvloader_bin.cpp.bakmsvc drvloader_bin.cpp >nul 2>&1
if exist kvc_bin.cpp.bakmsvc copy /Y kvc_bin.cpp.bakmsvc kvc_bin.cpp >nul 2>&1
del /q elevator_bin.cpp.bakmsvc drvloader_bin.cpp.bakmsvc kvc_bin.cpp.bakmsvc >nul 2>&1
echo [*] MSVC build completed successfully.
goto :EOF

