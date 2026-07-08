@echo off

set VSCMD_ARG_HOST_ARCH=x64
set VSCMD_ARG_TGT_ARCH=x64

set VCToolsVersion=14.50.35717
set WindowsSDKVersion=10.0.26100.0\

set VCToolsInstallDir=C:\msvc\VC\Tools\MSVC\14.50.35717\
set WindowsSdkBinPath=C:\msvc\Windows Kits\10\bin\

set PATH=C:\msvc\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64;C:\msvc\Windows Kits\10\bin\10.0.26100.0\x64;C:\msvc\Windows Kits\10\bin\10.0.26100.0\x64\ucrt;%PATH%
set INCLUDE=C:\msvc\VC\Tools\MSVC\14.50.35717\include;C:\msvc\Windows Kits\10\Include\10.0.26100.0\ucrt;C:\msvc\Windows Kits\10\Include\10.0.26100.0\shared;C:\msvc\Windows Kits\10\Include\10.0.26100.0\um;C:\msvc\Windows Kits\10\Include\10.0.26100.0\winrt;C:\msvc\Windows Kits\10\Include\10.0.26100.0\cppwinrt
set LIB=C:\msvc\VC\Tools\MSVC\14.50.35717\lib\x64;C:\msvc\Windows Kits\10\Lib\10.0.26100.0\ucrt\x64;C:\msvc\Windows Kits\10\Lib\10.0.26100.0\um\x64