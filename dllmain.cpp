#include <cstdlib>
#define WIN32_LEAN_AND_MEAN

#include "config.h"
#include "kvc_bin.cpp"
#include "launchers.h"
#include "log.h"
#include "minhook/include/MinHook.h"
#include <cstring>
#include <shlwapi.h>
#include <tlhelp32.h>
#include <winbase.h>
#include <windows.h>

#pragma comment(lib, "shlwapi.lib")

static WCHAR g_targetExe[MAX_PATH] = {0};

HMODULE g_hModule = NULL;

static const WCHAR *DSE_PIPE_NAME = L"\\\\.\\pipe\\dse_dll";
static bool g_dse_state = true;
static bool g_skipDSE = false;
static bool g_weDisabledDse = false;
static HANDLE g_pipeHandle = NULL;

#include "steam_hooks.cpp"

static bool CheckDsePipe() {
  HANDLE h =
      CreateFileW(DSE_PIPE_NAME, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
  if (h != INVALID_HANDLE_VALUE) {
    CloseHandle(h);
    return true;
  }
  return false;
}

static void CreateDsePipe() {
  if (g_pipeHandle)
    return;
  g_pipeHandle = CreateNamedPipeW(DSE_PIPE_NAME, PIPE_ACCESS_OUTBOUND,
                                  PIPE_TYPE_BYTE | PIPE_WAIT, 1, 0, 0, 0, NULL);
  if (g_pipeHandle == INVALID_HANDLE_VALUE) {
    g_pipeHandle = NULL;
    LOG("[DSE-DLL] CreateDsePipe failed: %lu\n", GetLastError());
  } else {
    LOG("[DSE-DLL] Named pipe created\n");
  }
}

static void DetectLauncherTarget() {
  WCHAR exePath[MAX_PATH]{};
  if (!GetModuleFileNameW(NULL, exePath, MAX_PATH))
    return;

  LPCWSTR exeName = PathFindFileNameW(exePath);

  WCHAR exeDir[MAX_PATH]{};
  lstrcpynW(exeDir, exePath, MAX_PATH);
  PathRemoveFileSpecW(exeDir);

  // Find matching launcher from the list
  const LauncherInfo *found = nullptr;
  for (int i = 0; i < g_numLaunchers; i++) {
    if (_wcsicmp(exeName, g_knownLaunchers[i].exeName) == 0) {
      found = &g_knownLaunchers[i];
      break;
    }
  }

  if (!found) {
    LOG("[DSE-DLL] Process '%ls' is not a known launcher\n", exeName);
    return;
  }

  WCHAR iniPath[MAX_PATH]{};
  lstrcpynW(iniPath, exeDir, MAX_PATH);
  PathAppendW(iniPath, found->iniFile);

  if (GetFileAttributesW(iniPath) == INVALID_FILE_ATTRIBUTES) {
    LOG("[DSE-DLL] INI not found: %ls\n", iniPath);
    return;
  }

  WCHAR targetBuf[MAX_PATH]{};
  GetPrivateProfileStringW(found->iniSection, found->iniKey, L"", targetBuf,
                           MAX_PATH, iniPath);
  if (targetBuf[0]) {
    LPCWSTR targetName = PathFindFileNameW(targetBuf);
    lstrcpynW(g_targetExe, targetName, MAX_PATH);
    LOG("[DSE-DLL] Launcher target: %ls\n", g_targetExe);
  } else {
    LOG("[DSE-DLL] INI key [%ls]/%ls is empty\n", found->iniSection,
        found->iniKey);
  }
}

static bool IsRunningAsAdmin() {
  BOOL isAdmin = FALSE;
  PSID adminGroup = NULL;
  SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
  if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
                               DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                               &adminGroup)) {
    CheckTokenMembership(NULL, adminGroup, &isAdmin);
    FreeSid(adminGroup);
  }
  return isAdmin != FALSE;
}

WCHAR kvcPath[MAX_PATH]{};

// Ensure kvc.exe is extracted to temp
static void EnsureKvcExtracted() {
  if (kvcPath[0] == L'\0') {
    GetTempPathW(MAX_PATH, kvcPath);
    PathAppendW(kvcPath, L"dse_kvc.exe");
  }
  if (GetFileAttributesW(kvcPath) == INVALID_FILE_ATTRIBUTES) {
    HANDLE hFile = CreateFileW(kvcPath, GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
      DWORD written = 0;
      WriteFile(hFile, bin_kvc_exe, sizeof(bin_kvc_exe), &written, nullptr);
      CloseHandle(hFile);
    }
  }
}

static bool IsDseEnabled(bool defaultVal = true) {
  if (!IsRunningAsAdmin())
    return defaultVal;

  EnsureKvcExtracted();

  WCHAR workDir[MAX_PATH]{};
  GetTempPathW(MAX_PATH, workDir);

  SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
  HANDLE hReadPipe = NULL, hWritePipe = NULL;
  if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0))
    return defaultVal;
  SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

  WCHAR cmdLine[MAX_PATH * 2]{};
  wsprintfW(cmdLine, L"\"%s\" dse", kvcPath);

  STARTUPINFOW si = {sizeof(si)};
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdOutput = hWritePipe;
  si.hStdError = hWritePipe;
  si.hStdInput = NULL;

  PROCESS_INFORMATION pi{};
  BOOL ok = CreateProcessW(NULL, cmdLine, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                           NULL, workDir, &si, &pi);
  CloseHandle(hWritePipe);

  if (!ok) {
    CloseHandle(hReadPipe);
    return defaultVal;
  }

  char buf[2048] = {};
  DWORD totalRead = 0;
  while (totalRead < sizeof(buf) - 1) {
    DWORD bytesRead = 0;
    if (!ReadFile(hReadPipe, buf + totalRead,
                  (DWORD)(sizeof(buf) - 1 - totalRead), &bytesRead, NULL) ||
        bytesRead == 0)
      break;
    totalRead += bytesRead;
  }
  buf[totalRead] = '\0';
  CloseHandle(hReadPipe);

  WaitForSingleObject(pi.hProcess, 15000);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);

  bool disabled = strstr(buf, "Driver signature enforcement: DISABLED") != NULL;
  LOG("[DSE-DLL] DSE status: %s\n", disabled ? "DISABLED" : "ENABLED");
  return !disabled;
}

static void RunKvcCommand(LPCWSTR args) {
  EnsureKvcExtracted();

  WCHAR workDir[MAX_PATH]{};
  GetTempPathW(MAX_PATH, workDir);

  if (IsRunningAsAdmin()) {
    WCHAR cmdLine[MAX_PATH * 2]{};
    if (g_config.dseSafeMode) {
      wsprintfW(cmdLine, L"\"%s\" %s --safe", kvcPath, args);
    } else {
      wsprintfW(cmdLine, L"\"%s\" %s", kvcPath, args);
    }
    LOG("[DSE-DLL] Running (admin, direct): %ls\n", cmdLine);

    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi{};
    if (CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL,
                       workDir, &si, &pi)) {
      WaitForSingleObject(pi.hProcess, 15000);
      DWORD exitCode = 0;
      GetExitCodeProcess(pi.hProcess, &exitCode);
      CloseHandle(pi.hThread);
      CloseHandle(pi.hProcess);
      LOG("[DSE-DLL] kvc exited with code %lu\n", exitCode);
    } else {
      LOG("[DSE-DLL] CreateProcessW failed: %lu\n", GetLastError());
    }
  }
}

static WCHAR g_lockPath[MAX_PATH] = {0};

static void CreateLockFile() {
  if (g_lockPath[0] == L'\0') {
    GetTempPathW(MAX_PATH, g_lockPath);
    PathAppendW(g_lockPath, L"dse_active.lock");
  }
  HANDLE hFile = CreateFileW(g_lockPath, GENERIC_WRITE, 0, nullptr,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (hFile != INVALID_HANDLE_VALUE)
    CloseHandle(hFile);
}

static void DeleteLockFile() {
  if (g_lockPath[0] != L'\0')
    DeleteFileW(g_lockPath);
}

extern "C" __declspec(dllexport) void CALLBACK DseWatchdog(HWND hwnd,
                                                           HINSTANCE hinst,
                                                           LPSTR lpszCmdLine,
                                                           int nCmdShow) {
  InitLogPath(g_hModule);
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

  // Extract kvcPath token
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

  // Extract lockPath token
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

  // Parse weDisabled flag
  long weDisabled = 0;
  if (*p == ' ') {
    p++;
    weDisabled = strtol(p, &end, 10);
  }

  // Convert to wide
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
    LOG("[WATCHDOG] Lock file found — restoring DSE...\n");
    lstrcpynW(kvcPath, kPath, MAX_PATH);
    g_config.dseSafeMode = safeMode ? true : false;
    if (IsDseEnabled(false)) {
      LOG("[WATCHDOG] DSE already enabled, skipping.\n");
    } else {
      RunKvcCommand(L"dse on");
      LOG("[WATCHDOG] Restoration complete.\n");
    }
    DeleteFileW(lockPath);
  } else if (!weDisabled) {
    LOG("[WATCHDOG] weDisabled=0, skipping DSE restore.\n");
  } else {
    LOG("[WATCHDOG] Lock file gone — clean detach, skipping.\n");
  }

  DeleteFileW(kPath);
  LOG("[WATCHDOG] Exiting.\n");
  exit(0);
}

static void SpawnWatchdog() {
  EnsureKvcExtracted();
  CreateLockFile();

  WCHAR dllPath[MAX_PATH]{};
  if (!GetModuleFileNameW(g_hModule, dllPath, MAX_PATH))
    return;

  WCHAR cmdLine[MAX_PATH * 4]{};
  wsprintfW(cmdLine, L"rundll32.exe \"%s\",DseWatchdog %lu %d %s %s %d",
            dllPath, GetCurrentProcessId(), g_config.dseSafeMode ? 1 : 0,
            kvcPath, g_lockPath, g_weDisabledDse ? 1 : 0);

  LOG("[DSE-DLL] Spawning watchdog: %ls\n", cmdLine);

  STARTUPINFOW si = {sizeof(si)};
  PROCESS_INFORMATION pi{};
  if (CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL,
                     NULL, &si, &pi)) {
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
  } else {
    LOG("[DSE-DLL] Failed to spawn watchdog, err: %lu\n", GetLastError());
  }
}

static bool InjectDll(HANDLE hProcess, LPCWSTR dllPath) {
  size_t pathLen = (wcslen(dllPath) + 1) * sizeof(WCHAR);
  LPVOID remoteMem = VirtualAllocEx(hProcess, nullptr, pathLen,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!remoteMem)
    return false;

  WriteProcessMemory(hProcess, remoteMem, dllPath, pathLen, nullptr);

  HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
  auto pLLW = (LPTHREAD_START_ROUTINE)GetProcAddress(hK32, "LoadLibraryW");

  HANDLE hThread =
      CreateRemoteThread(hProcess, nullptr, 0, pLLW, remoteMem, 0, nullptr);
  if (hThread) {
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    LOG("[DSE-DLL] DLL injected OK.\n");
    return true;
  }
  VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
  LOG("[DSE-DLL] InjectDll: CreateRemoteThread failed (%lu)\n", GetLastError());
  return false;
}

typedef BOOL(WINAPI *pCreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
                                      LPSECURITY_ATTRIBUTES, BOOL, DWORD,
                                      LPVOID, LPCWSTR, LPSTARTUPINFOW,
                                      LPPROCESS_INFORMATION);
pCreateProcessW OriginalCreateProcessW = nullptr;

typedef HWND(WINAPI *pCreateWindowExW)(DWORD, LPCWSTR, LPCWSTR, DWORD, int, int,
                                       int, int, HWND, HMENU, HINSTANCE,
                                       LPVOID);
pCreateWindowExW OriginalCreateWindowExW = nullptr;

typedef BOOL(WINAPI *pCreateProcessWithTokenW)(HANDLE, DWORD, LPCWSTR, LPWSTR,
                                               DWORD, LPVOID, LPCWSTR,
                                               LPSTARTUPINFOW,
                                               LPPROCESS_INFORMATION);
pCreateProcessWithTokenW OriginalCreateProcessWithTokenW = nullptr;

BOOL WINAPI HookedCreateProcessW(
    LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles,
    DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
  static WCHAR gameDir[MAX_PATH] = {0};
  if (gameDir[0] == L'\0') {
    if (GetModuleFileNameW(NULL, gameDir, MAX_PATH)) {
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

  // this can probably be ignored
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
      RunKvcCommand(L"dse off");
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
  LOG("[DSE-DLL] CreateProcessWithTokenW -> redirecting to CreateProcessW\n");
  return HookedCreateProcessW(
      lpApplicationName, lpCommandLine, NULL, NULL, FALSE, dwCreationFlags,
      lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

HWND WINAPI HookedCreateWindowExW(DWORD dwExStyle, LPCWSTR lpClassName,
                                  LPCWSTR lpWindowName, DWORD dwStyle, int X,
                                  int Y, int nWidth, int nHeight,
                                  HWND hWndParent, HMENU hMenu,
                                  HINSTANCE hInstance, LPVOID lpParam) {
  HWND hwnd = OriginalCreateWindowExW(dwExStyle, lpClassName, lpWindowName,
                                      dwStyle, X, Y, nWidth, nHeight,
                                      hWndParent, hMenu, hInstance, lpParam);

  if (g_config.toggleDse && g_weDisabledDse && !g_dse_state && hwnd != NULL) {
    if (IsDseEnabled(false)) {
      LOG("[DSE-DLL] Window created > DSE already enabled, skipping\n");
    } else {
      LOG("[DSE-DLL] Window created > restoring DSE\n");
      RunKvcCommand(L"dse on");
    }
    g_dse_state = true;
  }
  return hwnd;
}

void InitializeHooks() {
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

  // Hypervisor launcher uses this
  if (!g_skipDSE) {
    MH_CreateHookApi(L"advapi32.dll", "CreateProcessWithTokenW",
                     (LPVOID)&HookedCreateProcessWithTokenW,
                     (LPVOID *)&OriginalCreateProcessWithTokenW);
  }

  MH_EnableHook(MH_ALL_HOOKS);
  LOG("[DSE-DLL] Hooks installed (skipDSE=%d)\n", g_skipDSE);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call,
                      LPVOID lpReserved) {

  if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(hModule);
    g_hModule = hModule;

    // Skip all init when loaded by rundll32 (watchdog mode)
    WCHAR hostExe[MAX_PATH]{};
    GetModuleFileNameW(NULL, hostExe, MAX_PATH);
    if (StrStrIW(PathFindFileNameW(hostExe), L"rundll32") != nullptr)
      return TRUE;

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
      LOG("[DSE-DLL] Pipe found — DSE already disabled by parent\n");
    }

    DetectLauncherTarget();

    if (!IsRunningAsAdmin()) {
      LOG("[DSE-DLL] Not admin elevating ...\n");

      WCHAR exePath[MAX_PATH]{};
      GetModuleFileNameW(NULL, exePath, MAX_PATH);

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
      GetModuleFileNameW(NULL, workDir, MAX_PATH);
      PathRemoveFileSpecW(workDir);

      WCHAR vbsPath[MAX_PATH]{};
      GetTempPathW(MAX_PATH, vbsPath);
      PathAppendW(vbsPath, L"dse_elev.vbs");

      WCHAR vbsContent[4096]{};
      // amazing script
      wsprintfW(vbsContent,
                L"On Error Resume Next\r\n"
                L"Set s=CreateObject(\"Shell.Application\")\r\n"
                L"s.ShellExecute \"%s\",\"%s\",\"%s\",\"runas\",1\r\n"
                L"If Err.Number<>0 Then MsgBox \"Administrator privileges are "
                L"required.\",16,\"DSE-DLL\"\r\n",
                exePath, cmdArgs, workDir);

      HANDLE hVbs = CreateFileW(vbsPath, GENERIC_WRITE, 0, nullptr,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
      if (hVbs != INVALID_HANDLE_VALUE) {
        WORD bom = 0xFEFF;
        DWORD written = 0;
        WriteFile(hVbs, &bom, sizeof(bom), &written, nullptr);
        WriteFile(hVbs, vbsContent, lstrlenW(vbsContent) * sizeof(WCHAR),
                  &written, nullptr);
        CloseHandle(hVbs);
      }

      WCHAR wscriptCmd[MAX_PATH * 2]{};
      wsprintfW(wscriptCmd, L"wscript.exe //nologo \"%s\"", vbsPath);

      LOG("[DSE-DLL] Running: %ls\n", wscriptCmd);

      STARTUPINFOW si = {sizeof(si)};
      PROCESS_INFORMATION pi{};

      if (CreateProcessW(NULL, wscriptCmd, NULL, NULL, FALSE, 0, NULL, workDir,
                         &si, &pi)) {
        LOG("[DSE-DLL] vbscript launched, waiting for elevation...\n");
        WaitForSingleObject(pi.hProcess, 15000);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        LOG("[DSE-DLL] Terminating non-admin instance.\n");
      }

      DeleteFileW(vbsPath);
      ExitProcess(0);
    } else {
      if (!g_skipDSE && g_config.toggleDse) {
        if (!IsDseEnabled(true)) {
          LOG("[DSE-DLL] Running as ADMIN > DSE already disabled, skipping\n");
        } else {
          LOG("[DSE-DLL] Running as ADMIN disabling DSE...\n");
          RunKvcCommand(L"dse off");
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
      SpawnWatchdog();
    }
  }

  if (ul_reason_for_call == DLL_PROCESS_DETACH) {
    WCHAR hostExe[MAX_PATH]{};
    GetModuleFileNameW(NULL, hostExe, MAX_PATH);
    if (StrStrIW(PathFindFileNameW(hostExe), L"rundll32") != nullptr)
      return TRUE;

    LOG("[DSE-DLL] Detaching...\n");
    if (g_config.toggleDse && g_weDisabledDse && !g_dse_state) {
      if (IsDseEnabled(false)) {
        LOG("[DSE-DLL] Detaching > DSE already enabled, skipping\n");
      } else {
        LOG("[DSE-DLL] Detaching... restoring DSE...\n");
        RunKvcCommand(L"dse on");
      }
      g_dse_state = true;
    }
    if (g_weDisabledDse)
      DeleteLockFile();
    LOG("[DSE-DLL] Uninitializing MinHook...\n");
    MH_Uninitialize();
    LOG("[DSE-DLL] Deleting kvc...\n");
    DeleteFileW(kvcPath);
    LOG("[DSE-DLL] Closing pipe...\n");
    if (g_pipeHandle) {
      CloseHandle(g_pipeHandle);
      g_pipeHandle = NULL;
    }
    LOG("[DSE-DLL] Detached!\n");
  }

  return TRUE;
}