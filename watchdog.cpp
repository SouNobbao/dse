#include "watchdog.h"

#include "common.h"
#include "config.h"
#include "events.h"
#include "kvc.h"
#include "log.h"

#include <cstdlib>
#include <cstring>

static constexpr LPCWSTR kWatchdogCommandTemplate =
    L"rundll32.exe \"%s\",DseWatchdog %lu %d %s %s %d";

extern "C" __declspec(dllexport) void CALLBACK DseWatchdog(HWND hwnd,
                                                           HINSTANCE hinst,
                                                           LPSTR lpszCmdLine,
                                                           int nCmdShow) {
  (void)hwnd;
  (void)hinst;
  (void)nCmdShow;

  InitLogPath(g_hModule);
  LoadDseConfig(g_hModule);
  g_loggingEnabled = g_config.logging;
  LOG("[WATCHDOG] Started with args: %s\n", lpszCmdLine);

  char *p = lpszCmdLine;
  char *end = nullptr;

  long pid = strtol(p, &end, 10);
  if (end == p || *end != ' ') {
    LOG("[WATCHDOG] Bad PID\n");
    return;
  }
  p = end + 1;

  long safeMode = strtol(p, &end, 10);
  if (end == p || *end != ' ') {
    LOG("[WATCHDOG] Bad safeMode\n");
    return;
  }
  p = end + 1;

  char *kvcStart = p;
  while (*p && *p != ' ')
    p++;
  char kvcA[MAX_PATH] = {0};
  int kvcLen = (int)(p - kvcStart);
  if (kvcLen <= 0 || kvcLen >= MAX_PATH) {
    LOG("[WATCHDOG] Bad kvcPath\n");
    return;
  }
  memcpy(kvcA, kvcStart, kvcLen);

  if (*p == ' ')
    p++;

  char *lockStart = p;
  while (*p && *p != ' ' && *p != '\r' && *p != '\n')
    p++;
  char lockA[MAX_PATH] = {0};
  int lockLen = (int)(p - lockStart);
  if (lockLen <= 0 || lockLen >= MAX_PATH) {
    LOG("[WATCHDOG] Bad lockPath\n");
    return;
  }
  memcpy(lockA, lockStart, lockLen);

  long weDisabled = 0;
  if (*p == ' ') {
    p++;
    weDisabled = strtol(p, &end, 10);
  }

  WCHAR kPath[MAX_PATH] = {0};
  WCHAR lockPath[MAX_PATH] = {0};
  MultiByteToWideChar(CP_ACP, 0, kvcA, -1, kPath, MAX_PATH);
  MultiByteToWideChar(CP_ACP, 0, lockA, -1, lockPath, MAX_PATH);

  LOG("[WATCHDOG] PID=%ld safe=%ld weDisabled=%ld\n", pid, safeMode,
      weDisabled);
  LOG("[WATCHDOG] kvc: %s\n", kvcA);
  LOG("[WATCHDOG] lock: %s\n", lockA);

  HANDLE hProc = OpenProcess(SYNCHRONIZE, FALSE, (DWORD)pid);
  if (!hProc) {
    LOG("[WATCHDOG] OpenProcess failed! err: %lu\n", GetLastError());
    return;
  }

  LOG("[WATCHDOG] Waiting for game to exit...\n");
  WaitForSingleObject(hProc, INFINITE);
  CloseHandle(hProc);
  LOG("[WATCHDOG] Game exited!\n");

  if (weDisabled && GetFileAttributesW(lockPath) != INVALID_FILE_ATTRIBUTES) {
    LOG("[WATCHDOG] Lock file found - restoring DSE...\n");
    lstrcpynW(kvcPath, kPath, MAX_PATH);
    g_config.dseSafeMode = safeMode ? true : false;
    if (IsDseEnabled(false)) {
      LOG("[WATCHDOG] DSE already enabled, skipping.\n");
    } else {
      EnableDse();
      LOG("[WATCHDOG] Restoration complete.\n");
    }
    DeleteFileW(lockPath);
  } else if (!weDisabled) {
    LOG("[WATCHDOG] weDisabled=0, skipping DSE restore.\n");
  } else {
    LOG("[WATCHDOG] Lock file gone - clean detach, skipping.\n");
  }

  DeleteFileW(kPath);
  LOG("[WATCHDOG] Exiting.\n");
  exit(0);
}

void SpawnWatchdog(bool weDisabledDse) {
  EnsureKvcExtracted();
  CreateLockFile();

  WCHAR dllPath[MAX_PATH]{};
  if (!GetModuleFileNameW(g_hModule, dllPath, MAX_PATH))
    return;

  WCHAR cmdLine[MAX_PATH * 4]{};
  wsprintfW(cmdLine, kWatchdogCommandTemplate, dllPath, GetCurrentProcessId(),
            g_config.dseSafeMode ? 1 : 0, kvcPath, GetLockPath(),
            weDisabledDse ? 1 : 0);

  LOG("[DSE-DLL] Spawning watchdog: %ls\n", cmdLine);

  STARTUPINFOW si = {sizeof(si)};
  PROCESS_INFORMATION pi{};
  if (CreateProcessW(nullptr, cmdLine, nullptr, nullptr, FALSE,
                     CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
  } else {
    LOG("[DSE-DLL] Failed to spawn watchdog, err: %lu\n", GetLastError());
  }
}
