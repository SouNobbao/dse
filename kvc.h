#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

extern WCHAR kvcPath[MAX_PATH];

bool IsRunningAsAdmin();
void EnsureKvcExtracted();
bool IsDseEnabled(bool defaultVal = true);
void RunKvcCommand(LPCWSTR args);
void DisableDse();
void EnableDse();
void DeleteKvcFile();
