#include "config.h"

#include "common.h"

#include <cstdio>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

DseConfig g_config = {true, false, false, false, L"", false, {}, {}};

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

static void ReadIniStringList(LPCWSTR section, LPCWSTR key, LPCWSTR iniPath, std::vector<std::wstring> &outList) {
	WCHAR buf[1024]{};
	GetPrivateProfileStringW(section, key, L"", buf, ARRAYSIZE(buf), iniPath);

	std::wstring s(buf);
	size_t pos = 0;
	while ((pos = s.find(L',')) != std::wstring::npos) {
		std::wstring token = s.substr(0, pos);
		token.erase(0, token.find_first_not_of(L" \t\r\n"));
		token.erase(token.find_last_not_of(L" \t\r\n") + 1);
		if (!token.empty())
			outList.push_back(token);
		s.erase(0, pos + 1);
	}
	s.erase(0, s.find_first_not_of(L" \t\r\n"));
	size_t last = s.find_last_not_of(L" \t\r\n");
	if (last != std::wstring::npos)
		s.erase(last + 1);
	if (!s.empty())
		outList.push_back(s);
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
						   L"disabled, patcher will not run.\ntoggleDse=true\n"
						   L"; Enable/disable Steam API hooks\nsteamHooks=false\n"
						   L"; Enable coldloader support (for games that need it)\ncoldloaderhooks=false\n"
						   L"; Path to original Steam client for coldloaderhooks\nsteam_path=\n"
						   L"; Enable/disable logging output\nlogging=false\n"
						   L"; Disable some Steam API hooks when using Reloaded-II\n"
						   L"reloaded=false\n\n"
						   L"; Problematic services to stop or delete (Format: ServiceName:ACTION)\n"
						   L"problematic_services=\n\n"
						   L"; Problematic tasks to kill (comma separated executable names)\n"
						   L"problematic_tasks=\n");

			fclose(file);
		}
		return;
	}

	g_config.toggleDse = ReadIniBool(L"dse", L"toggleDse", true, iniPath);
	g_config.steamHooks = ReadIniBool(L"dse", L"steamHooks", false, iniPath);
	g_config.coldloaderhooks = ReadIniBool(L"dse", L"coldloaderhooks", false, iniPath);

	WCHAR pathBuf[MAX_PATH]{};
	GetPrivateProfileStringW(L"dse", L"steam_path", L"", pathBuf, ARRAYSIZE(pathBuf), iniPath);
	g_config.steam_path = pathBuf;

	g_config.reloaded = ReadIniBool(L"dse", L"reloaded", false, iniPath);
	g_config.logging = ReadIniBool(L"dse", L"logging", false, iniPath);

	std::vector<std::wstring> rawServices;
	ReadIniStringList(L"dse", L"problematic_services", iniPath, rawServices);
	for (const auto &svc : rawServices) {
		size_t colon = svc.find(L':');
		if (colon != std::wstring::npos) {
			std::wstring name = svc.substr(0, colon);
			std::wstring actionStr = svc.substr(colon + 1);

			name.erase(0, name.find_first_not_of(L" \t\r\n"));
			size_t nameLast = name.find_last_not_of(L" \t\r\n");
			if (nameLast != std::wstring::npos)
				name.erase(nameLast + 1);

			actionStr.erase(0, actionStr.find_first_not_of(L" \t\r\n"));
			size_t actionLast = actionStr.find_last_not_of(L" \t\r\n");
			if (actionLast != std::wstring::npos)
				actionStr.erase(actionLast + 1);

			ServiceActionType action = ServiceActionType::STOP;
			if (_wcsicmp(actionStr.c_str(), L"DELETE") == 0) {
				action = ServiceActionType::DELETE_SVC;
			}
			g_config.problematicServices.push_back({name, action});
		}
	}

	ReadIniStringList(L"dse", L"problematic_tasks", iniPath, g_config.problematicTasks);
}
