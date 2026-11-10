#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <shlwapi.h>

#include <filesystem>

extern HMODULE g_hModule;
extern WCHAR g_targetExe[MAX_PATH];
extern bool g_wasOffFromStart;
extern bool g_wasToggled;
extern bool g_isLauncher;

constexpr LPCWSTR kDseIniName = L"dse.ini";
constexpr LPCWSTR kTempSubdir = L"dsedll";

inline std::filesystem::path GetDseTempDir() {
	std::error_code ec;
	std::filesystem::path dir = std::filesystem::temp_directory_path(ec);
	if (ec)
		return {};
	dir /= kTempSubdir;
	std::filesystem::create_directories(dir, ec);
	return dir;
}

inline bool GetDseTempPath(LPCWSTR filename, WCHAR (&out)[MAX_PATH]) {
	std::filesystem::path dir = GetDseTempDir();
	if (dir.empty())
		return false;
	lstrcpynW(out, (dir / filename).c_str(), MAX_PATH);
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

inline bool ShouldPassThrough(LPCWSTR exePath, LPCWSTR curDir) {
	static WCHAR s_gameDir[MAX_PATH]{};
	if (!s_gameDir[0] && GetModuleFileNameW(nullptr, s_gameDir, MAX_PATH)) {
		PathRemoveFileSpecW(s_gameDir);
		PathAddBackslashW(s_gameDir);
	}

	WCHAR resolved[MAX_PATH]{};
	if (!PathIsRelativeW(exePath)) {
		lstrcpynW(resolved, exePath, MAX_PATH);
	} else {
		WCHAR cwd[MAX_PATH]{};
		LPCWSTR base = (curDir && curDir[0]) ? curDir : (GetCurrentDirectoryW(MAX_PATH, cwd) ? cwd : nullptr);
		if (base)
			PathCombineW(resolved, base, exePath);
	}

	LPCWSTR checkPath = resolved[0] ? resolved : exePath;
	if (s_gameDir[0] && StrStrIW(checkPath, s_gameDir) != checkPath)
		return true;
	return IsPassthroughExe(PathFindFileNameW(exePath));
}

inline void GetLaunchedExePath(LPCWSTR app, LPCWSTR cmdLine, WCHAR (&out)[MAX_PATH]) {
	if (app && app[0]) {
		lstrcpynW(out, app, MAX_PATH);
		return;
	}
	if (!cmdLine || !cmdLine[0])
		return;
	int argc = 0;
	LPWSTR *argv = CommandLineToArgvW(cmdLine, &argc);
	if (!argv)
		return;
	if (argc > 0)
		lstrcpynW(out, argv[0], MAX_PATH);
	LocalFree(argv);
}
