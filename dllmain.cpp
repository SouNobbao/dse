#define WIN32_LEAN_AND_MEAN

#include "kvc_bin.cpp"
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

#ifdef _STEAM
#include "steam_hooks.cpp"
#endif

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

#ifdef _IMNOTSURE_IFNEEDED
static bool EnablePrivilege(LPCWSTR privilegeName) {
  HANDLE tok{};
  if (!OpenProcessToken(GetCurrentProcess(),
                        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
    return false;
  LUID luid{};
  if (!LookupPrivilegeValueW(nullptr, privilegeName, &luid)) {
    CloseHandle(tok);
    return false;
  }
  TOKEN_PRIVILEGES tp{};
  tp.PrivilegeCount = 1;
  tp.Privileges[0].Luid = luid;
  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  AdjustTokenPrivileges(tok, FALSE, &tp, 0, nullptr, nullptr);
  bool ok = (GetLastError() == ERROR_SUCCESS);
  CloseHandle(tok);
  return ok;
}
#endif

static void RunKvcCommand(LPCWSTR args) {
  WCHAR kvcPath[MAX_PATH]{};
  GetTempPathW(MAX_PATH, kvcPath);
  PathAppendW(kvcPath, L"dse_kvc.exe");

  WCHAR workDir[MAX_PATH]{};
  GetTempPathW(MAX_PATH, workDir);

  if (GetFileAttributesW(kvcPath) == INVALID_FILE_ATTRIBUTES) {
    HANDLE hFile = CreateFileW(kvcPath, GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
      DWORD written = 0;
      WriteFile(hFile, bin_kvc_exe, sizeof(bin_kvc_exe), &written, nullptr);
      CloseHandle(hFile);
    }
  }

  if (IsRunningAsAdmin()) {
    WCHAR cmdLine[MAX_PATH * 2]{};
    wsprintfW(cmdLine, L"\"%s\" %s", kvcPath, args);
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

  DeleteFileW(kvcPath);
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
  LOG("[DSE-DLL] InjectDll: CreateRemoteThread failed (%lu)\n",
          GetLastError());
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

  RunKvcCommand(L"dse off");

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

HWND WINAPI HookedCreateWindowExW(DWORD dwExStyle, LPCWSTR lpClassName,
                                  LPCWSTR lpWindowName, DWORD dwStyle, int X,
                                  int Y, int nWidth, int nHeight,
                                  HWND hWndParent, HMENU hMenu,
                                  HINSTANCE hInstance, LPVOID lpParam) {
  HWND hwnd = OriginalCreateWindowExW(dwExStyle, lpClassName, lpWindowName,
                                      dwStyle, X, Y, nWidth, nHeight,
                                      hWndParent, hMenu, hInstance, lpParam);

  static bool dseTurnedOn = false;
  if (!dseTurnedOn && hwnd != NULL) {
    LOG("[DSE-DLL] Window created!\n");
    dseTurnedOn = true;
    RunKvcCommand(L"dse on");
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
  MH_EnableHook(MH_ALL_HOOKS);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call,
                      LPVOID lpReserved) {
  switch (ul_reason_for_call) {
  case DLL_PROCESS_ATTACH:
    DisableThreadLibraryCalls(hModule);
    g_hModule = hModule;
#ifdef _DEBUG
    SetupLogConsole(g_hModule);
#endif
    LOG("[DSE-DLL] Attached to PID %lu\n", GetCurrentProcessId());

    #ifdef _IMNOTSURE_IFNEEDED
      EnablePrivilege(L"SeDebugPrivilege");
      EnablePrivilege(L"SeImpersonatePrivilege");
      EnablePrivilege(L"SeAssignPrimaryTokenPrivilege");
      EnablePrivilege(L"SeShutdownPrivilege");
    #endif

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
      // this never reuns tbf
      /*  else {
        LOG("[DSE-DLL] CreateProcessW for mshta failed: %lu\n",
                GetLastError());
        MessageBoxW(NULL,
                    L"Administrator privileges are required.\n"
                    L"Please run the game as Administrator.",
                    L"DSE-DLL", MB_OK | MB_ICONERROR);
      } */
      DeleteFileW(vbsPath);
      ExitProcess(0);
    } else {
      LOG("[DSE-DLL] Running as ADMIN disabling DSE...\n");
      RunKvcCommand(L"dse off");
    }

    InitializeHooks();
    #ifdef _STEAM
    InitSteamHooks();
    #endif
    break;

  case DLL_PROCESS_DETACH:
    if (IsRunningAsAdmin()) {
      LOG("[DSE-DLL] Detaching... restoring DSE...\n");
      RunKvcCommand(L"dse on");
    }
    MH_Uninitialize();
    break;
  }
  return TRUE;
}

