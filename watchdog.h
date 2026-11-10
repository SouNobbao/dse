#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// entry for rundll32
extern "C" __declspec(dllexport) void CALLBACK DseWatchdog(HWND hwnd,
														   HINSTANCE hinst,
														   LPSTR lpszCmdLine,
														   int nCmdShow);

namespace Watchdog {

// entrypoint
void run(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow);

// rundll launcher
void spawn(bool wasOffFromStart, bool wasToggled);

}
