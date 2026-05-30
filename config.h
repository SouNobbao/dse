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
	bool toggleDse;
	bool steamHooks;
	bool logging;
	std::vector<ProblematicService> problematicServices;
	std::vector<std::wstring> problematicTasks;
};

extern DseConfig g_config;

void LoadDseConfig(HMODULE hModule);
