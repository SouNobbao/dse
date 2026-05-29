#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

bool InjectDll(HANDLE hProcess, LPCWSTR dllPath);
