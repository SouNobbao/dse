#include "events.h"

#include "common.h"
#include "log.h"

#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

static HANDLE g_pipeHandle = nullptr;
static WCHAR g_lockPath[MAX_PATH] = {0};

bool CheckDsePipe() {
  HANDLE h = CreateFileW(kDsePipeName, GENERIC_READ, 0, nullptr, OPEN_EXISTING,
                         0, nullptr);
  if (h != INVALID_HANDLE_VALUE) {
    CloseHandle(h);
    return true;
  }
  return false;
}

void CreateDsePipe() {
  if (g_pipeHandle)
    return;

  g_pipeHandle =
      CreateNamedPipeW(kDsePipeName, PIPE_ACCESS_OUTBOUND,
                       PIPE_TYPE_BYTE | PIPE_WAIT, 1, 0, 0, 0, nullptr);
  if (g_pipeHandle == INVALID_HANDLE_VALUE) {
    g_pipeHandle = nullptr;
    LOG("[DSE-DLL] CreateDsePipe failed: %lu\n", GetLastError());
  } else {
    LOG("[DSE-DLL] Named pipe created\n");
  }
}

void CloseDsePipe() {
  if (!g_pipeHandle)
    return;

  CloseHandle(g_pipeHandle);
  g_pipeHandle = nullptr;
}

void CreateLockFile() {
  if (g_lockPath[0] == L'\0') {
    GetTempPathW(MAX_PATH, g_lockPath);
    PathAppendW(g_lockPath, kLockFileName);
  }

  HANDLE hFile = CreateFileW(g_lockPath, GENERIC_WRITE, 0, nullptr,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (hFile != INVALID_HANDLE_VALUE)
    CloseHandle(hFile);
}

void DeleteLockFile() {
  if (g_lockPath[0] != L'\0')
    DeleteFileW(g_lockPath);
}

LPCWSTR GetLockPath() { return g_lockPath; }
