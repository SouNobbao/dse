#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

extern HMODULE g_hModule;

static constexpr LPCWSTR kDseIniName = L"dse.ini";
static constexpr LPCWSTR kPatcherName = L"dse_patcher.exe";
static constexpr LPCWSTR kLockFileName = L"dse_off_from_start.lock";
static constexpr LPCWSTR kToggledLockFileName = L"dse_toggled.lock";
static constexpr LPCWSTR kElevationScriptName = L"dse_elev.vbs";

static constexpr LPCWSTR kElevationVbsTemplate =
	L"On Error Resume Next\r\n"
	L"Set s=CreateObject(\"Shell.Application\")\r\n"
	L"s.ShellExecute \"%s\",\"%s\",\"%s\",\"runas\",1\r\n"
	L"If Err.Number<>0 Then MsgBox \"Administrator privileges are "
	L"required.\",16,\"DSE-DLL\"\r\n";
