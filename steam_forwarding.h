#pragma once
#include <windows.h>

static int HookAllExports(HMODULE hSource, HMODULE hTarget);
static int RebindImports(LPCSTR dllName, HMODULE hEmulator);
