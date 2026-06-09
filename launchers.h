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
    {L"steamclient_loader_x64.exe", L"ColdClientLoader.ini", L"SteamClient",
     L"Exe"},
};

static const int g_numLaunchers =
    sizeof(g_knownLaunchers) / sizeof(g_knownLaunchers[0]);

static bool DetectLauncherTarget(WCHAR *targetExe, DWORD maxLen, bool *inLauncher) {
  if (!targetExe || maxLen == 0 || !inLauncher)
    return false;
  targetExe[0] = L'\0';
  *inLauncher = false;

  WCHAR exePath[MAX_PATH]{};
  if (!GetModuleFileNameW(nullptr, exePath, MAX_PATH))
    return false;

  LPCWSTR exeName = PathFindFileNameW(exePath);

  WCHAR exeDir[MAX_PATH]{};
  lstrcpynW(exeDir, exePath, MAX_PATH);
  PathRemoveFileSpecW(exeDir);

  const LauncherInfo *found = nullptr;
  for (int i = 0; i < g_numLaunchers; i++) {
    if (_wcsicmp(exeName, g_knownLaunchers[i].exeName) == 0) {
      found = &g_knownLaunchers[i];
      break;
    }
  }

  if (!found) {
    LOG("[DSE-DLL] Process '%ls' is not a known launcher\n", exeName);
    return false;
  }

  WCHAR iniPath[MAX_PATH]{};
  lstrcpynW(iniPath, exeDir, MAX_PATH);
  PathAppendW(iniPath, found->iniFile);
  *inLauncher = true;
  
  if (GetFileAttributesW(iniPath) == INVALID_FILE_ATTRIBUTES) {
    LOG("[DSE-DLL] INI not found: %ls\n", iniPath);
    return false;
  }

  WCHAR targetBuf[MAX_PATH]{};
  GetPrivateProfileStringW(found->iniSection, found->iniKey, L"", targetBuf,
                           MAX_PATH, iniPath);
  if (!targetBuf[0]) {
    LOG("[DSE-DLL] INI key [%ls]/%ls is empty\n", found->iniSection,
        found->iniKey);
    return false;
  }

  LPCWSTR targetName = PathFindFileNameW(targetBuf);
  lstrcpynW(targetExe, targetName, maxLen);
  LOG("[DSE-DLL] Launcher target: %ls\n", targetExe);
  return true;
}