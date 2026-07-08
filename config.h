#pragma once

#define WIN32_LEAN_AND_MEAN
#include <string>
#include "c_std/vector/vector.h"
#include "c_std/string/std_string.h"
#include <windows.h>

enum class ServiceActionType {
	STOP,
	DELETE_SVC
};

struct ProblematicService {
	String* name; // UTF-8 String*
	ServiceActionType action;
};

struct DseConfig {
	bool toggleDse;
	bool steamHooks;
	bool reloaded;
	bool coldloaderhooks;
	String* steam_path;

	bool logging;
	Vector* problematicServices; // stores ProblematicService*
	Vector* problematicTasks;    // stores String*
};

extern DseConfig g_config;

void LoadDseConfig(HMODULE hModule);
