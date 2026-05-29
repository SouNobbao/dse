#pragma once

#define WIN32_LEAN_AND_MEAN
#include <minwindef.h>
#include <windows.h>

typedef BOOL(WINAPI *pCreateProcessW_t)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
										LPSECURITY_ATTRIBUTES, BOOL, DWORD,
										LPVOID, LPCWSTR, LPSTARTUPINFOW,
										LPPROCESS_INFORMATION);

extern pCreateProcessW_t OriginalCreateProcessW;
extern WCHAR kvcPath[MAX_PATH];

bool IsRunningAsAdmin();
void EnsureKvcExtracted();
bool IsDseEnabled(bool defaultVal = true);
void RunKvcCommand(LPCWSTR args);
void DisableDse();
void EnableDse();
void DeleteKvcFile();
