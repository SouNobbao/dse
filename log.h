#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef _DEBUG

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <shlwapi.h>
#include <stdio.h>

static WCHAR g_logPath[MAX_PATH] = {0};

static void InitLogPath(HMODULE hModule) {
  if (g_logPath[0] != L'\0')
    return;
  if (!hModule)
    return;

  WCHAR path[MAX_PATH]{};
  if (!GetModuleFileNameW(hModule, path, MAX_PATH))
    return;
  PathRemoveFileSpecW(path);
  PathAppendW(path, L"dse-dll.log");
  lstrcpynW(g_logPath, path, MAX_PATH);
}

static void AppendLogLine(const char *line) {
  if (!line || !line[0])
    return;
  if (g_logPath[0] == L'\0')
    return;

  HANDLE hFile = CreateFileW(g_logPath, FILE_APPEND_DATA,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                             OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (hFile == INVALID_HANDLE_VALUE)
    return;

  DWORD bytes = static_cast<DWORD>(std::strlen(line));
  DWORD written = 0;
  WriteFile(hFile, line, bytes, &written, nullptr);
  CloseHandle(hFile);
}

static void Log(const char *fmt, ...) {
  if (!fmt)
    return;

  char buffer[2048]{};
  va_list args;
  va_start(args, fmt);
  vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, fmt, args);
  va_end(args);

  printf("%s", buffer);
  AppendLogLine(buffer);
}

static void SetupLogConsole(HMODULE hModule) {
  InitLogPath(hModule);
  AllocConsole();
  FILE *dummy;
  freopen_s(&dummy, "CONOUT$", "w", stdout);
  freopen_s(&dummy, "CONOUT$", "w", stderr);
  freopen_s(&dummy, "CONIN$", "r", stdin);
  Log("[DSE-DLL] Console initialized.\n");
}

#define LOG(fmt, ...) Log(fmt, ##__VA_ARGS__)

#else

static void SetupLogConsole(HMODULE) {}
#define LOG(fmt, ...) ((void)0)

#endif
