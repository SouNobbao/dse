#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

extern "C" __declspec(dllexport) void CALLBACK DseWatchdog(HWND hwnd,
                                                           HINSTANCE hinst,
                                                           LPSTR lpszCmdLine,
                                                           int nCmdShow);

void SpawnWatchdog(bool weDisabledDse);
