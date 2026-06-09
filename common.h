#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlwapi.h>

extern HMODULE g_hModule;

static constexpr LPCWSTR kDseIniName = L"dse.ini";
static constexpr LPCWSTR kPatcherName = L"dse_patcher.exe";
static constexpr LPCWSTR kLockFileName = L"dse_off_from_start.lock";
static constexpr LPCWSTR kToggledLockFileName = L"dse_toggled.lock";
static constexpr LPCWSTR kElevationScriptName = L"dse_elev.ps1";

static constexpr LPCWSTR kElevationPs1Template =
	L"Start-Process -FilePath \"%s\" -ArgumentList \"%s\" -WorkingDirectory \"%s\" -Verb RunAs\r\n";

static inline bool IsPassthroughExe(LPCWSTR exeName) {
    if (!exeName) return false;
    return StrStrIW(exeName, L"drvloader")   != nullptr ||
           StrStrIW(exeName, L"crashpad_handler") != nullptr ||
           StrStrIW(exeName, L"watchdog")     != nullptr ||
           StrStrIW(exeName, L"rundll32")     != nullptr ||
           StrStrIW(exeName, L"wmic")         != nullptr ||
           StrStrIW(exeName, L"crs-handler")  != nullptr ||
		   StrStrIW(exeName, L"crash_handler")  != nullptr ||
		   StrStrIW(exeName, L"crashhandler")  != nullptr ||
		   StrStrIW(exeName, L"crashreport")  != nullptr;
}