#define WIN32_LEAN_AND_MEAN
#include <shlwapi.h>
#include <windows.h>

#pragma comment(lib, "shlwapi.lib")

extern "C" __declspec(dllexport) void DseLoaderInit(void) {}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call,
                      LPVOID lpReserved) {
  if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(hModule);

    WCHAR loaderDir[MAX_PATH]{};
    if (!GetModuleFileNameW(hModule, loaderDir, MAX_PATH))
      return TRUE;
    PathRemoveFileSpecW(loaderDir);

    WCHAR dsePath[MAX_PATH]{};
    lstrcpynW(dsePath, loaderDir, MAX_PATH);
    PathAppendW(dsePath, L"dse.dll");

    if (GetFileAttributesW(dsePath) != INVALID_FILE_ATTRIBUTES) {
      LoadLibraryW(dsePath);
    }
  }
  return TRUE;
}
