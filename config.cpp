#include "config.h"

#include "common.h"

#include <cstdio>
#include <wchar.h>
#include <wctype.h>
#include <shlwapi.h>
#include "c_std/string/std_string.h"

#pragma comment(lib, "shlwapi.lib")

// default config order
DseConfig g_config = {true, false, false, false, nullptr, false, nullptr, nullptr};

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

static void ReadIniStringList(LPCWSTR section, LPCWSTR key, LPCWSTR iniPath, Vector* outList) {
	WCHAR buf[1024]{};
	GetPrivateProfileStringW(section, key, L"", buf, ARRAYSIZE(buf), iniPath);
	WCHAR *ctx = nullptr;
	WCHAR *tok = wcstok(buf, L",", &ctx);
	while (tok) {
		WCHAR *start = tok;
		while (*start && iswspace((wint_t)*start)) start++;
		WCHAR *end = start + wcslen(start);
		while (end > start && iswspace((wint_t)*(end - 1))) *(--end) = L'\0';
		if (*start) {
			String* str = string_from_unicode(start);
			vector_push_back(outList, &str);
		}
		tok = wcstok(nullptr, L",", &ctx);
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
	if (pathBuf[0]) {
		String* tmpPath = string_from_unicode(pathBuf);
		g_config.steam_path = tmpPath;
	}

	g_config.reloaded = ReadIniBool(L"dse", L"reloaded", false, iniPath);
	g_config.logging = ReadIniBool(L"dse", L"logging", false, iniPath);

	Vector* rawServices = vector_create(sizeof(String*));
	ReadIniStringList(L"dse", L"problematic_services", iniPath, rawServices);
	size_t rawCount = vector_size(rawServices);
	for (size_t ri = 0; ri < rawCount; ++ri) {
		String** psvc = (String**)vector_at(rawServices, ri);
		String* svcStr = psvc ? *psvc : nullptr;
		if (!svcStr) continue;
		wchar_t* svc_w = string_to_unicode(string_c_str(svcStr));
		if (!svc_w) {
			string_deallocate(svcStr);
			continue;
		}

		wchar_t *colonPtr = wcschr(svc_w, L':');
		if (colonPtr) {
			size_t colonIndex = colonPtr - svc_w;
			wchar_t *dup = _wcsdup(svc_w);
			if (dup) {
				dup[colonIndex] = L'\0';
				wchar_t *nameStart = dup;
				while (*nameStart && iswspace((wint_t)*nameStart)) nameStart++;
				wchar_t *nameEnd = nameStart + wcslen(nameStart);
				while (nameEnd > nameStart && iswspace((wint_t)*(nameEnd - 1))) *(--nameEnd) = L'\0';

				wchar_t *actionStart = dup + colonIndex + 1;
				while (*actionStart && iswspace((wint_t)*actionStart)) actionStart++;
				wchar_t *actionEnd = actionStart + wcslen(actionStart);
				while (actionEnd > actionStart && iswspace((wint_t)*(actionEnd - 1))) *(--actionEnd) = L'\0';

				if (*nameStart) {
					ServiceActionType action = ServiceActionType::STOP;
					if (_wcsicmp(actionStart, L"DELETE") == 0) {
						action = ServiceActionType::DELETE_SVC;
					}
					String* nameStr = string_from_unicode(nameStart);
					ProblematicService* ps = new ProblematicService();
					ps->name = nameStr;
					ps->action = action;
					if (!g_config.problematicServices)
						g_config.problematicServices = vector_create(sizeof(ProblematicService*));
					vector_push_back(g_config.problematicServices, &ps);
				}
				free(dup);
			}
		}
		free(svc_w);
		string_deallocate(svcStr);
	}
	vector_deallocate(rawServices);

	if (!g_config.problematicTasks)
		g_config.problematicTasks = vector_create(sizeof(String*));
	ReadIniStringList(L"dse", L"problematic_tasks", iniPath, g_config.problematicTasks);
}
