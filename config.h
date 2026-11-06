#pragma once

#define WIN32_LEAN_AND_MEAN
#include "c_std/vector/vector.h"
#include "c_std/string/std_string.h"
#include <windows.h>

enum class ServiceActionType {
	STOP,
	DELETE_SVC
};

struct ProblematicService {
	String *name;
	ServiceActionType action;
};

struct DseConfig {
	bool toggleDse;
	bool steamHooks;
	bool reloaded;
	bool coldloaderhooks;
	bool steamApiForward;
	String *steam_path;

	bool logging;
	bool ignoreWarnings;
	Vector *problematicServices;
	Vector *problematicTasks;
};

extern DseConfig g_config;

void LoadDseConfig(HMODULE hModule);
void FreeDseConfig();
