#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

struct LauncherInfo {
  const WCHAR *exeName;
  const WCHAR *iniFile;
  const WCHAR *iniSection;
  const WCHAR *iniKey;
};

static const LauncherInfo g_knownLaunchers[] = {
    {L"hypervisor-launcher.exe", L"reflex.ini", L"launcher", L"game"},
    {L"steamclient_loader_x64.exe", L"ColdClientLoader.ini",
     L"SteamClient", L"Exe"},
};

static const int g_numLaunchers =
    sizeof(g_knownLaunchers) / sizeof(g_knownLaunchers[0]);
