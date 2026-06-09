#pragma once

#define WIN32_LEAN_AND_MEAN
#include "log.h"
#include <shlwapi.h>
#include <windows.h>

#pragma comment(lib, "shlwapi.lib")

struct LauncherInfo {
  const WCHAR *exeName;
  const WCHAR *iniFile;
  const WCHAR *iniSection;
  const WCHAR *iniKey;
};

static const LauncherInfo g_knownLaunchers[] = {
    {L"hypervisor-launcher.exe", L"reflex.ini", L"launcher", L"game"},
    {L"hypervisor-launcher.exe", L"reflex.ini", L"config", L"target"},
    {L"steamclient_loader_x64.exe", L"ColdClientLoader.ini", L"SteamClient",
     L"Exe"},
};

static const int g_numLaunchers =
    sizeof(g_knownLaunchers) / sizeof(g_knownLaunchers[0]);

static bool DetectLauncherTarget(WCHAR *targetExe, DWORD maxLen) {
  if (!targetExe || maxLen == 0) return false;
  targetExe[0] = L'\0';

  WCHAR exePath[MAX_PATH]{};
  if (!GetModuleFileNameW(nullptr, exePath, MAX_PATH)) return false;

  LPCWSTR exeName = PathFindFileNameW(exePath);

  WCHAR exeDir[MAX_PATH]{};
  lstrcpynW(exeDir, exePath, MAX_PATH);
  PathRemoveFileSpecW(exeDir);

  bool foundAny = false;

  for (int i = 0; i < g_numLaunchers; i++) {
    if (_wcsicmp(exeName, g_knownLaunchers[i].exeName) != 0)
      continue;

    foundAny = true;
    const LauncherInfo *info = &g_knownLaunchers[i];

    WCHAR iniPath[MAX_PATH]{};
    lstrcpynW(iniPath, exeDir, MAX_PATH);
    PathAppendW(iniPath, info->iniFile);

    if (GetFileAttributesW(iniPath) == INVALID_FILE_ATTRIBUTES) {
      LOG("[DSE-DLL] INI not found: %ls\n", iniPath);
      continue;
    }

    WCHAR targetBuf[MAX_PATH]{};
    GetPrivateProfileStringW(info->iniSection, info->iniKey, L"",
                             targetBuf, MAX_PATH, iniPath);

    if (!targetBuf[0]) {
      LOG("[DSE-DLL] INI key [%ls]/%ls is empty, trying next\n",
          info->iniSection, info->iniKey);
      continue;
    }

    LPCWSTR targetName = PathFindFileNameW(targetBuf);
    lstrcpynW(targetExe, targetName, maxLen);
    LOG("[DSE-DLL] Launcher target: %ls\n", targetExe);
    return true;
  }

  if (!foundAny)
    LOG("[DSE-DLL] Process '%ls' is not a known launcher\n", exeName);

  return false;
}