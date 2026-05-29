#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

extern bool g_loggingEnabled;

void InitLogPath(HMODULE hModule);
void Log(const char *fmt, ...);
void SetupLogConsole(HMODULE hModule);

#define LOG(fmt, ...)                                                          \
  do {                                                                         \
    if (g_loggingEnabled)                                                      \
      Log(fmt, ##__VA_ARGS__);                                                 \
  } while (0)
