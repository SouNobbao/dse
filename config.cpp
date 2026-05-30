#include "config.h"

#include "common.h"

#include <cstdio>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

DseConfig g_config = {true, false, false};

static bool ReadIniBool(LPCWSTR section, LPCWSTR key, bool defaultVal,
						LPCWSTR iniPath) {
	WCHAR buf[16]{};
	GetPrivateProfileStringW(section, key, defaultVal ? L"true" : L"false", buf,
							 ARRAYSIZE(buf), iniPath);
	if (_wcsicmp(buf, L"true") == 0 || _wcsicmp(buf, L"1") == 0 ||
		_wcsicmp(buf, L"yes") == 0)
		return true;
	if (_wcsicmp(buf, L"false") == 0 || _wcsicmp(buf, L"0") == 0 ||
		_wcsicmp(buf, L"no") == 0)
		return false;
	return defaultVal;
}

static void GetDseIniPath(HMODULE hModule, WCHAR *outPath, DWORD maxLen) {
	outPath[0] = L'\0';
	WCHAR dllDir[MAX_PATH]{};
	if (!GetModuleFileNameW(hModule, dllDir, MAX_PATH))
		return;
	PathRemoveFileSpecW(dllDir);
	lstrcpynW(outPath, dllDir, maxLen);
	PathAppendW(outPath, kDseIniName);
}

void LoadDseConfig(HMODULE hModule) {
	WCHAR iniPath[MAX_PATH]{};
	GetDseIniPath(hModule, iniPath, MAX_PATH);

	if (GetFileAttributesW(iniPath) == INVALID_FILE_ATTRIBUTES) {
		FILE *file = _wfopen(iniPath, L"w");
		if (file) {
			fwprintf(file, L"[dse]\n; Automatically toggle DSE. If DSE was already "
						   L"disabled, drvloader will not run.\ntoggleDse=true\n"
						   L"; Enable/disable Steam "
						   L"API hooks\nsteamHooks=false\n; Enable/disable logging "
						   L"output\nlogging=false");

			fclose(file);
		}
		return;
	}

	g_config.toggleDse = ReadIniBool(L"dse", L"toggleDse", true, iniPath);

	g_config.steamHooks = ReadIniBool(L"dse", L"steamHooks", false, iniPath);
	g_config.logging = ReadIniBool(L"dse", L"logging", false, iniPath);
}
