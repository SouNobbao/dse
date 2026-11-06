#pragma once

#define WIN32_LEAN_AND_MEAN
#include <string>
#include <vector>
#include <windows.h>

enum class ServiceActionType {
	STOP,
	DELETE_SVC
};

struct ProblematicService {
	std::wstring name;
	ServiceActionType action;
};

struct DseConfig {
	bool toggleDse = true;
	bool steamHooks = false;
	bool reloaded = false;
	bool coldloaderhooks = false;
	bool steamApiForward = false;
	std::wstring steam_path;

	bool logging = false;
	bool ignoreWarnings = false;
	std::vector<ProblematicService> problematicServices;
	std::vector<std::wstring> problematicTasks;
};

extern DseConfig g_config;

void LoadDseConfig(HMODULE hModule);
void FreeDseConfig();
