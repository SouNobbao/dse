#include "events.h"

#include "common.h"
#include "log.h"

#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

static WCHAR g_lockPath[MAX_PATH] = {0};
static WCHAR g_toggledPath[MAX_PATH] = {0};

static void EnsureLockPath() {
  if (g_lockPath[0] == L'\0') {
    GetTempPathW(MAX_PATH, g_lockPath);
    PathAppendW(g_lockPath, kLockFileName);
  }
}

static void EnsureToggledPath() {
  if (g_toggledPath[0] == L'\0') {
    GetTempPathW(MAX_PATH, g_toggledPath);
    PathAppendW(g_toggledPath, kToggledLockFileName);
  }
}

void CreateDseOffFromStartLock() {
  EnsureLockPath();
  HANDLE hFile = CreateFileW(g_lockPath, GENERIC_WRITE, 0, nullptr,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (hFile != INVALID_HANDLE_VALUE)
    CloseHandle(hFile);
  LOG("[DSE-DLL] Created dse-off-from-start lock: %ls\n", g_lockPath);
}

void DeleteDseOffFromStartLock() {
  EnsureLockPath();
  if (GetFileAttributesW(g_lockPath) != INVALID_FILE_ATTRIBUTES) {
    DeleteFileW(g_lockPath);
    LOG("[DSE-DLL] Deleted dse-off-from-start lock\n");
  }
}

bool DseWasOffFromStart() {
  EnsureLockPath();
  return GetFileAttributesW(g_lockPath) != INVALID_FILE_ATTRIBUTES;
}

void CreateDseToggledLock() {
  EnsureToggledPath();
  HANDLE hFile = CreateFileW(g_toggledPath, GENERIC_WRITE, 0, nullptr,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (hFile != INVALID_HANDLE_VALUE)
    CloseHandle(hFile);
}

void DeleteDseToggledLock() {
  EnsureToggledPath();
  if (GetFileAttributesW(g_toggledPath) != INVALID_FILE_ATTRIBUTES)
    DeleteFileW(g_toggledPath);
}

bool DseWasToggled() {
  EnsureToggledPath();
  return GetFileAttributesW(g_toggledPath) != INVALID_FILE_ATTRIBUTES;
}
