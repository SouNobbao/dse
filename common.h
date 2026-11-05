#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlwapi.h>

extern HMODULE g_hModule;

constexpr LPCWSTR kDseIniName = L"dse.ini";
constexpr LPCWSTR kPatcherName = L"dse_patcher.exe";
constexpr LPCWSTR kLockFileName = L"dse_off_from_start.lock";
constexpr LPCWSTR kToggledLockFileName = L"dse_toggled.lock";
constexpr LPCWSTR kElevationScriptName = L"dse_elev.ps1";
constexpr LPCWSTR kTempSubdir = L"dsedll";

// Returns %TEMP%\dsedll\<filename>, creating the directory if needed.
inline bool GetDseTempPath(LPCWSTR filename, WCHAR (&out)[MAX_PATH]) {
	GetTempPathW(MAX_PATH, out);
	PathAppendW(out, kTempSubdir);
	CreateDirectoryW(out, nullptr); // ok if exists
	PathAppendW(out, filename);
	return true;
}

inline bool IsPassthroughExe(LPCWSTR exeName) {
	if (!exeName)
		return false;
	return StrStrIW(exeName, L"watchdog.exe") ||
		   StrStrIW(exeName, L"drvloader") != nullptr ||
		   StrStrIW(exeName, L"crashpad_handler") != nullptr ||
		   StrStrIW(exeName, L"rundll32") != nullptr ||
		   StrStrIW(exeName, L"wmic") != nullptr ||
		   StrStrIW(exeName, L"crs-handler") != nullptr ||
		   StrStrIW(exeName, L"crash_handler") != nullptr ||
		   StrStrIW(exeName, L"crashhandler") != nullptr ||
		   StrStrIW(exeName, L"crashreport") != nullptr;
}

inline bool IsHostPassthrough() {
	WCHAR hostPath[MAX_PATH]{};
	return GetModuleFileNameW(nullptr, hostPath, MAX_PATH) &&
		   IsPassthroughExe(PathFindFileNameW(hostPath));
}