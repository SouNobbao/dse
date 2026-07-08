#include "log.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <shlwapi.h>
#include "c_std/string/std_string.h"

#pragma comment(lib, "shlwapi.lib")

bool g_loggingEnabled = false;

static WCHAR g_logPath[MAX_PATH] = {0};

void InitLogPath(HMODULE hModule) {
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

  String* tmpStr = string_create(line);
  DWORD bytes = static_cast<DWORD>(string_length(tmpStr));
  string_deallocate(tmpStr);
  DWORD written = 0;
  WriteFile(hFile, line, bytes, &written, nullptr);
  CloseHandle(hFile);
}

void Log(const char *fmt, ...) {
  if (!fmt)
    return;

  char buffer[2048]{};
  va_list args;
  va_start(args, fmt);
  vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, fmt, args);
  va_end(args);

  static bool s_hasLast = false;
  static char s_lastLine[sizeof(buffer)]{};
  
  if (s_hasLast) {
    String* a = string_create(buffer);
    String* b = string_create(s_lastLine);
    bool equal = (string_compare(a, b) == 0);
    string_deallocate(a);
    string_deallocate(b);
    if (equal) return;
  }
  s_hasLast = true;
  strcpy_s(s_lastLine, sizeof(s_lastLine), buffer);

  printf("%s", buffer);
  AppendLogLine(buffer);
}

void SetupLogConsole(HMODULE hModule) {
  if (!g_loggingEnabled)
    return;
  InitLogPath(hModule);
  AllocConsole();
  FILE *dummy;
  freopen_s(&dummy, "CONOUT$", "w", stdout);
  freopen_s(&dummy, "CONOUT$", "w", stderr);
  freopen_s(&dummy, "CONIN$", "r", stdin);
  Log("[DSE-DLL] Console initialized.\n");
}
