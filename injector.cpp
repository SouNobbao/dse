#include "injector.h"

#include "log.h"

bool InjectDll(HANDLE hProcess, LPCWSTR dllPath) {
  size_t pathLen = (wcslen(dllPath) + 1) * sizeof(WCHAR);
  LPVOID remoteMem = VirtualAllocEx(hProcess, nullptr, pathLen,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!remoteMem)
    return false;

  if (!WriteProcessMemory(hProcess, remoteMem, dllPath, pathLen, nullptr)) {
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    LOG("[DSE-DLL] InjectDll: WriteProcessMemory failed (%lu)\n",
        GetLastError());
    return false;
  }

  HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
  auto pLLW = (LPTHREAD_START_ROUTINE)GetProcAddress(hK32, "LoadLibraryW");
  if (!pLLW) {
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    LOG("[DSE-DLL] InjectDll: LoadLibraryW not found (%lu)\n", GetLastError());
    return false;
  }

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
