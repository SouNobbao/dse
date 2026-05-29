#include <cstdlib>
#define WIN32_LEAN_AND_MEAN

#include "common.h"
#include "config.h"
#include "events.h"
#include "injector.h"
#include "kvc.h"
#include "launchers.h"
#include "log.h"
#include "minhook/include/MinHook.h"
#include "watchdog.h"

#include <cstring>
#include <shlwapi.h>
#include <windows.h>

#pragma comment(lib, "shlwapi.lib")

static WCHAR g_targetExe[MAX_PATH] = {0};
extern "C" __declspec(dllexport) void DseDll(void) {}

HMODULE g_hModule = nullptr;

static bool g_dse_state = true;
static bool g_skipDSE = false;
static bool g_weDisabledDse = false;

#include "steam_hooks.cpp"

static bool IsRundll32Host() {
  WCHAR hostExe[MAX_PATH]{};
  GetModuleFileNameW(nullptr, hostExe, MAX_PATH);
  return StrStrIW(PathFindFileNameW(hostExe), L"rundll32") != nullptr;
}

static constexpr LPCWSTR kWscriptCommandTemplate =
    L"wscript.exe //nologo \"%s\"";

static void RelaunchElevatedAndExit() {
  LOG("[DSE-DLL] Not admin elevating ...\n");

  WCHAR exePath[MAX_PATH]{};
  GetModuleFileNameW(nullptr, exePath, MAX_PATH);

  LPCWSTR fullCmdLine = GetCommandLineW();
  LPCWSTR cmdArgs = L"";
  if (fullCmdLine) {
    if (fullCmdLine[0] == L'"') {
      LPCWSTR end = wcschr(fullCmdLine + 1, L'"');
      if (end)
        cmdArgs = end + 1;
    } else {
      LPCWSTR space = wcschr(fullCmdLine, L' ');
      if (space)
        cmdArgs = space;
    }
    while (*cmdArgs == L' ')
      cmdArgs++;
  }

  WCHAR workDir[MAX_PATH]{};
  GetModuleFileNameW(nullptr, workDir, MAX_PATH);
  PathRemoveFileSpecW(workDir);

  WCHAR vbsPath[MAX_PATH]{};
  GetTempPathW(MAX_PATH, vbsPath);
  PathAppendW(vbsPath, kElevationScriptName);

  WCHAR vbsContent[4096]{};
  wsprintfW(vbsContent, kElevationVbsTemplate, exePath, cmdArgs, workDir);

  HANDLE hVbs = CreateFileW(vbsPath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
  if (hVbs != INVALID_HANDLE_VALUE) {
    WORD bom = 0xFEFF;
    DWORD written = 0;
    WriteFile(hVbs, &bom, sizeof(bom), &written, nullptr);
    WriteFile(hVbs, vbsContent, lstrlenW(vbsContent) * sizeof(WCHAR), &written,
              nullptr);
    CloseHandle(hVbs);
  }

  WCHAR wscriptCmd[MAX_PATH * 2]{};
  wsprintfW(wscriptCmd, kWscriptCommandTemplate, vbsPath);

  LOG("[DSE-DLL] Running: %ls\n", wscriptCmd);

  STARTUPINFOW si = {sizeof(si)};
  PROCESS_INFORMATION pi{};

  if (CreateProcessW(nullptr, wscriptCmd, nullptr, nullptr, FALSE, 0, nullptr,
                     workDir, &si, &pi)) {
    LOG("[DSE-DLL] vbscript launched, waiting for elevation...\n");
    WaitForSingleObject(pi.hProcess, 15000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    LOG("[DSE-DLL] Terminating non-admin instance.\n");
  }

  DeleteFileW(vbsPath);
  ExitProcess(0);
}

typedef BOOL(WINAPI *pCreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
                                      LPSECURITY_ATTRIBUTES, BOOL, DWORD,
                                      LPVOID, LPCWSTR, LPSTARTUPINFOW,
                                      LPPROCESS_INFORMATION);
static pCreateProcessW OriginalCreateProcessW = nullptr;

typedef HWND(WINAPI *pCreateWindowExW)(DWORD, LPCWSTR, LPCWSTR, DWORD, int, int,
                                       int, int, HWND, HMENU, HINSTANCE,
                                       LPVOID);
static pCreateWindowExW OriginalCreateWindowExW = nullptr;

typedef BOOL(WINAPI *pCreateProcessWithTokenW)(HANDLE, DWORD, LPCWSTR, LPWSTR,
                                               DWORD, LPVOID, LPCWSTR,
                                               LPSTARTUPINFOW,
                                               LPPROCESS_INFORMATION);
static pCreateProcessWithTokenW OriginalCreateProcessWithTokenW = nullptr;

BOOL WINAPI HookedCreateProcessW(
    LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles,
    DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
  static WCHAR gameDir[MAX_PATH] = {0};
  if (gameDir[0] == L'\0') {
    if (GetModuleFileNameW(nullptr, gameDir, MAX_PATH)) {
      PathRemoveFileSpecW(gameDir);
      PathAddBackslashW(gameDir);
    }
  }

  auto isUnderGameDir = [&](LPCWSTR path) -> bool {
    if (!path || !path[0] || !gameDir[0])
      return false;
    return StrStrIW(path, gameDir) == path;
  };

  auto isInGameFolder = [&](LPCWSTR s, bool isCommandLine) -> bool {
    if (!s || !gameDir[0])
      return false;

    WCHAR exePath[MAX_PATH] = {0};
    if (!isCommandLine) {
      lstrcpynW(exePath, s, MAX_PATH);
    } else {
      const WCHAR *start = s;
      const WCHAR *end = nullptr;
      if (s[0] == L'"') {
        start = s + 1;
        end = wcschr(start, L'"');
      } else {
        for (end = s; *end && *end != L' ' && *end != L'\t'; ++end) {
        }
      }

      size_t len = end ? static_cast<size_t>(end - start) : wcslen(start);
      if (len >= MAX_PATH)
        len = MAX_PATH - 1;
      for (size_t i = 0; i < len; ++i)
        exePath[i] = start[i];
      exePath[len] = L'\0';
    }

    if (!exePath[0])
      return false;

    if (!PathIsRelativeW(exePath))
      return isUnderGameDir(exePath);

    if (lpCurrentDirectory && lpCurrentDirectory[0])
      return isUnderGameDir(lpCurrentDirectory);

    WCHAR cwd[MAX_PATH] = {0};
    if (GetCurrentDirectoryW(MAX_PATH, cwd))
      return isUnderGameDir(cwd);

    return false;
  };

  auto matchesIgnore = [&](LPCWSTR s, bool isCommandLine) -> bool {
    if (!s)
      return false;
    if (gameDir[0] && !isInGameFolder(s, isCommandLine))
      return true;
    return wcsstr(s, L"kvc.exe") != nullptr ||
           StrStrIW(s, L"crash") != nullptr ||
           StrStrIW(s, L"watchdog") != nullptr ||
           StrStrIW(s, L"rundll32") != nullptr;
  };

  if (matchesIgnore(lpApplicationName, false) ||
      matchesIgnore(lpCommandLine, true)) {
    return OriginalCreateProcessW(
        lpApplicationName, lpCommandLine, lpProcessAttributes,
        lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
        lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
  }

  LOG("[DSE-DLL] CreateProcessW intercepted: %ls\n",
      lpCommandLine ? lpCommandLine : L"(null)");

  if (g_targetExe[0] && !g_skipDSE) {
    LPCWSTR spawnedExe = lpApplicationName;
    if (!spawnedExe && lpCommandLine)
      spawnedExe = lpCommandLine;

    bool matches = false;
    if (spawnedExe) {
      LPCWSTR spawnedName = PathFindFileNameW(spawnedExe);
      if (spawnedName[0] == L'"')
        spawnedName++;
      matches = (StrStrIW(spawnedName, g_targetExe) != nullptr);
    }
    if (!matches) {
      LOG("[DSE-DLL] Exe does not match target '%ls', passing through\n",
          g_targetExe);
      return OriginalCreateProcessW(
          lpApplicationName, lpCommandLine, lpProcessAttributes,
          lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
          lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    }
  }

  if (g_config.toggleDse && g_dse_state) {
    if (!IsDseEnabled(true)) {
      LOG("[DSE-DLL] DSE already disabled, skipping dse off\n");
    } else {
      DisableDse();
      g_weDisabledDse = true;
    }
    g_dse_state = false;
  }

  DWORD flags = dwCreationFlags | CREATE_SUSPENDED;

  BOOL ok = OriginalCreateProcessW(
      lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
      bInheritHandles, flags, lpEnvironment, lpCurrentDirectory, lpStartupInfo,
      lpProcessInformation);

  if (ok && lpProcessInformation) {
    WCHAR dllPath[MAX_PATH]{};
    GetModuleFileNameW(g_hModule, dllPath, MAX_PATH);

    InjectDll(lpProcessInformation->hProcess, dllPath);

    if (!(dwCreationFlags & CREATE_SUSPENDED))
      ResumeThread(lpProcessInformation->hThread);
  }

  return ok;
}

BOOL WINAPI HookedCreateProcessWithTokenW(
    HANDLE hToken, DWORD dwLogonFlags, LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine, DWORD dwCreationFlags, LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation) {
  (void)hToken;
  (void)dwLogonFlags;

  LOG("[DSE-DLL] CreateProcessWithTokenW -> redirecting to CreateProcessW\n");
  return HookedCreateProcessW(lpApplicationName, lpCommandLine, nullptr,
                              nullptr, FALSE, dwCreationFlags, lpEnvironment,
                              lpCurrentDirectory, lpStartupInfo,
                              lpProcessInformation);
}

HWND WINAPI HookedCreateWindowExW(DWORD dwExStyle, LPCWSTR lpClassName,
                                  LPCWSTR lpWindowName, DWORD dwStyle, int X,
                                  int Y, int nWidth, int nHeight,
                                  HWND hWndParent, HMENU hMenu,
                                  HINSTANCE hInstance, LPVOID lpParam) {
  HWND hwnd = OriginalCreateWindowExW(dwExStyle, lpClassName, lpWindowName,
                                      dwStyle, X, Y, nWidth, nHeight,
                                      hWndParent, hMenu, hInstance, lpParam);

  if (g_config.toggleDse && g_weDisabledDse && !g_dse_state &&
      hwnd != nullptr) {
    if (IsDseEnabled(false)) {
      LOG("[DSE-DLL] Window created > DSE already enabled, skipping\n");
    } else {
      LOG("[DSE-DLL] Window created > restoring DSE\n");
      EnableDse();
    }
    g_dse_state = true;
  }
  return hwnd;
}

static void InitializeHooks() {
  LOG("[DSE-DLL] Initializing MinHook...\n");
  if (MH_Initialize() != MH_OK) {
    LOG("[DSE-DLL] MinHook init failed!\n");
    return;
  }

  MH_CreateHookApi(L"kernel32.dll", "CreateProcessW",
                   (LPVOID)&HookedCreateProcessW,
                   (LPVOID *)&OriginalCreateProcessW);

  MH_CreateHookApi(L"user32.dll", "CreateWindowExW",
                   (LPVOID)&HookedCreateWindowExW,
                   (LPVOID *)&OriginalCreateWindowExW);

  if (!g_skipDSE) {
    MH_CreateHookApi(L"advapi32.dll", "CreateProcessWithTokenW",
                     (LPVOID)&HookedCreateProcessWithTokenW,
                     (LPVOID *)&OriginalCreateProcessWithTokenW);
  }

  MH_EnableHook(MH_ALL_HOOKS);
  LOG("[DSE-DLL] Hooks installed (skipDSE=%d)\n", g_skipDSE);
}

static void OnProcessAttach(HMODULE hModule) {
  DisableThreadLibraryCalls(hModule);
  g_hModule = hModule;

  if (IsRundll32Host())
    return;

  LoadDseConfig(hModule);
  g_loggingEnabled = g_config.logging;

  SetupLogConsole(g_hModule);
  LOG("[DSE-DLL] Attached to PID %lu\n", GetCurrentProcessId());
  LOG("[DSE-DLL] Config: toggleDse=%d dseSafeMode=%d steamHooks=%d "
      "logging=%d\n",
      g_config.toggleDse, g_config.dseSafeMode, g_config.steamHooks,
      g_config.logging);

  if (CheckDsePipe()) {
    g_skipDSE = true;
    g_dse_state = false;
    LOG("[DSE-DLL] Pipe found - DSE already disabled by parent\n");
  }

  DetectLauncherTarget(g_targetExe, ARRAYSIZE(g_targetExe));

  if (!IsRunningAsAdmin()) {
    RelaunchElevatedAndExit();
  } else {
    if (!g_skipDSE && g_config.toggleDse) {
      if (!IsDseEnabled(true)) {
        LOG("[DSE-DLL] Running as ADMIN > DSE already disabled, skipping\n");
      } else {
        LOG("[DSE-DLL] Running as ADMIN disabling DSE...\n");
        DisableDse();
        g_weDisabledDse = true;
      }
      g_dse_state = false;
      CreateDsePipe();
    } else if (g_skipDSE) {
      LOG("[DSE-DLL] Skipping DSE disable (pipe detected)\n");
    } else {
      LOG("[DSE-DLL] DSE toggling disabled by config\n");
    }
  }

  InitializeHooks();
  if (g_config.steamHooks) {
    InitSteamHooks();
  } else {
    LOG("[DSE-DLL] Steam hooks disabled by config\n");
  }

  if (g_targetExe[0]) {
    LOG("[DSE-DLL] Launcher detected, skipping watchdog\n");
  } else {
    SpawnWatchdog(g_weDisabledDse);
  }
}

static void OnProcessDetach() {
  if (IsRundll32Host())
    return;

  LOG("[DSE-DLL] Detaching...\n");
  if (g_config.toggleDse && g_weDisabledDse && !g_dse_state) {
    if (IsDseEnabled(false)) {
      LOG("[DSE-DLL] Detaching > DSE already enabled, skipping\n");
    } else {
      LOG("[DSE-DLL] Detaching... restoring DSE...\n");
      EnableDse();
    }
    g_dse_state = true;
  }
  if (g_weDisabledDse)
    DeleteLockFile();
  LOG("[DSE-DLL] Uninitializing MinHook...\n");
  MH_Uninitialize();
  LOG("[DSE-DLL] Deleting kvc...\n");
  DeleteKvcFile();
  LOG("[DSE-DLL] Closing pipe...\n");
  CloseDsePipe();
  LOG("[DSE-DLL] Detached!\n");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call,
                      LPVOID lpReserved) {
  (void)lpReserved;

  if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    OnProcessAttach(hModule);
  else if (ul_reason_for_call == DLL_PROCESS_DETACH)
    OnProcessDetach();

  return TRUE;
}
