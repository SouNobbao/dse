#pragma once

#include <windows.h>

extern decltype(&CreateWindowExW) OriginalCreateWindowExW;
extern decltype(&CreateProcessW) OriginalCreateProcessW;


BOOL WINAPI HookedCreateProcessW(
	LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles,
	DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);

BOOL WINAPI HookedCreateProcessWithTokenW(
	HANDLE hToken, DWORD dwLogonFlags, LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine, DWORD dwCreationFlags, LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation);

HWND WINAPI HookedCreateWindowExW(DWORD dwExStyle, LPCWSTR lpClassName,
								  LPCWSTR lpWindowName, DWORD dwStyle, int X,
								  int Y, int nWidth, int nHeight,
								  HWND hWndParent, HMENU hMenu,
								  HINSTANCE hInstance, LPVOID lpParam);
