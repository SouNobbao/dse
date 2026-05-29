#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

struct DseConfig {
  bool toggleDse;
  bool dseSafeMode;
  bool steamHooks;
  bool logging;
};

extern DseConfig g_config;

void LoadDseConfig(HMODULE hModule);
