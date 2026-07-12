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

inline bool IsPassthroughExe(LPCWSTR exeName) {
    if (!exeName) return false;
    return StrStrIW(exeName, L"watchdog.exe") ||
           StrStrIW(exeName, L"drvloader")   != nullptr ||
           StrStrIW(exeName, L"crashpad_handler") != nullptr ||
           StrStrIW(exeName, L"rundll32")     != nullptr ||
           StrStrIW(exeName, L"wmic")         != nullptr ||
           StrStrIW(exeName, L"crs-handler")  != nullptr ||
		   StrStrIW(exeName, L"crash_handler")  != nullptr ||
		   StrStrIW(exeName, L"crashhandler")  != nullptr ||
		   StrStrIW(exeName, L"crashreport")  != nullptr;
}