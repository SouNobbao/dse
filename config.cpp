#include "config.h"

#include "common.h"

#include <cstdio>
#include <wchar.h>
#include <wctype.h>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

DseConfig g_config;  // defaults from in-class initializers

static std::wstring TrimWs(const wchar_t *s, const wchar_t *end) {
	while (s < end && iswspace((wint_t)*s))
		++s;
	while (end > s && iswspace((wint_t) * (end - 1)))
		--end;
	return std::wstring(s, end);
}

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
	WCHAR *ctx = nullptr;
	for (WCHAR *tok = wcstok(buf, L",", &ctx); tok; tok = wcstok(nullptr, L",", &ctx)) {
		std::wstring s = TrimWs(tok, tok + wcslen(tok));
		if (!s.empty())
			outList.push_back(std::move(s));
	}
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
						   L"; Forward emulator steam_api64.dll exports to steam_api64_o.dll\nsteamApiForward=false\n"
						   L"; Enable/disable logging output\nlogging=false\n"
						   L"; Skip warning prompts and proceed automatically\nignoreWarnings=false\n"
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
	g_config.steamApiForward = ReadIniBool(L"dse", L"steamApiForward", false, iniPath);

	WCHAR pathBuf[MAX_PATH]{};
	GetPrivateProfileStringW(L"dse", L"steam_path", L"", pathBuf, ARRAYSIZE(pathBuf), iniPath);
	if (pathBuf[0])
		g_config.steam_path = pathBuf;

	g_config.reloaded = ReadIniBool(L"dse", L"reloaded", false, iniPath);
	g_config.logging = ReadIniBool(L"dse", L"logging", false, iniPath);
	g_config.ignoreWarnings = ReadIniBool(L"dse", L"ignoreWarnings", false, iniPath);

	std::vector<std::wstring> rawServices;
	ReadIniStringList(L"dse", L"problematic_services", iniPath, rawServices);
	for (const std::wstring &entry : rawServices) {
		size_t colon = entry.find(L':');
		if (colon == std::wstring::npos)
			continue;
		const wchar_t *base = entry.c_str();
		std::wstring name = TrimWs(base, base + colon);
		if (name.empty())
			continue;
		std::wstring action = TrimWs(base + colon + 1, base + entry.size());
		ProblematicService ps;
		ps.name = std::move(name);
		ps.action = (_wcsicmp(action.c_str(), L"DELETE") == 0) ? ServiceActionType::DELETE_SVC : ServiceActionType::STOP;
		g_config.problematicServices.push_back(std::move(ps));
	}

	ReadIniStringList(L"dse", L"problematic_tasks", iniPath, g_config.problematicTasks);
}

void FreeDseConfig() {
	g_config.steam_path.clear();
	g_config.problematicServices.clear();
	g_config.problematicTasks.clear();
}
