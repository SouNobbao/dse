#include "kvc.h"

#include "common.h"
#include "config.h"
#include "kvc_bin.cpp"
#include "log.h"

#include <cstring>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

WCHAR kvcPath[MAX_PATH]{};

bool IsRunningAsAdmin() {
  BOOL isAdmin = FALSE;
  PSID adminGroup = nullptr;
  SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
  if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
                               DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                               &adminGroup)) {
    CheckTokenMembership(nullptr, adminGroup, &isAdmin);
    FreeSid(adminGroup);
  }
  return isAdmin != FALSE;
}

void EnsureKvcExtracted() {
  if (kvcPath[0] == L'\0') {
    GetTempPathW(MAX_PATH, kvcPath);
    PathAppendW(kvcPath, kKvcExeName);
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

bool IsDseEnabled(bool defaultVal) {
  if (!IsRunningAsAdmin())
    return defaultVal;

  EnsureKvcExtracted();

  WCHAR workDir[MAX_PATH]{};
  GetTempPathW(MAX_PATH, workDir);

  SECURITY_ATTRIBUTES sa = {sizeof(sa), nullptr, TRUE};
  HANDLE hReadPipe = nullptr, hWritePipe = nullptr;
  if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0))
    return defaultVal;
  if (!SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0)) {
    CloseHandle(hReadPipe);
    CloseHandle(hWritePipe);
    return defaultVal;
  }

  WCHAR cmdLine[MAX_PATH * 2]{};
  wsprintfW(cmdLine, L"\"%s\" dse", kvcPath);

  STARTUPINFOW si = {sizeof(si)};
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdOutput = hWritePipe;
  si.hStdError = hWritePipe;
  si.hStdInput = nullptr;

  PROCESS_INFORMATION pi{};
  BOOL ok = CreateProcessW(nullptr, cmdLine, nullptr, nullptr, TRUE,
                           CREATE_NO_WINDOW, nullptr, workDir, &si, &pi);
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
                  (DWORD)(sizeof(buf) - 1 - totalRead), &bytesRead, nullptr) ||
        bytesRead == 0)
      break;
    totalRead += bytesRead;
  }
  buf[totalRead] = '\0';
  CloseHandle(hReadPipe);

  WaitForSingleObject(pi.hProcess, 15000);
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);

  bool disabled =
      strstr(buf, "Driver signature enforcement: DISABLED") != nullptr;
  LOG("[DSE-DLL] DSE status: %s\n", disabled ? "DISABLED" : "ENABLED");
  return !disabled;
}

void RunKvcCommand(LPCWSTR args) {
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
    if (CreateProcessW(nullptr, cmdLine, nullptr, nullptr, FALSE,
                       CREATE_NO_WINDOW, nullptr, workDir, &si, &pi)) {
      WaitForSingleObject(pi.hProcess, 15000);
      DWORD exitCode = 0;
      GetExitCodeProcess(pi.hProcess, &exitCode);
      CloseHandle(pi.hThread);
      CloseHandle(pi.hProcess);
      LOG("[DSE-DLL] kvc exited with code %lu\n", exitCode);
    } else {
      LOG("[DSE-DLL] CreateProcessW failed: %lu\n", GetLastError());
    }
  } else {
    LOG("[DSE-DLL] Skipping kvc command because process is not elevated\n");
  }
}

void DisableDse() { RunKvcCommand(L"dse off"); }

void EnableDse() { RunKvcCommand(L"dse on"); }

void DeleteKvcFile() { DeleteFileW(kvcPath); }
