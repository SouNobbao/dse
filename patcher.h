#pragma once

#define WIN32_LEAN_AND_MEAN
#include <minwindef.h>
#include <windows.h>

typedef bool(WINAPI *pCreateProcessW_t)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
										LPSECURITY_ATTRIBUTES, bool, DWORD,
										LPVOID, LPCWSTR, LPSTARTUPINFOW,
										LPPROCESS_INFORMATION);

extern pCreateProcessW_t OriginalCreateProcessW;

bool IsRunningAsAdmin();
void EnsurePatcherExtracted();
bool IsDseEnabled(bool defaultVal = true);
void DisableDse();
void EnableDse();
void DeletePatcherFile();
