#define WIN32_LEAN_AND_MEAN

#include "checks.h"
#include "common.h"
#include "config.h"
#include "dse_hooks.h"
#include "injector.h"
#include "log.h"
#include "patcher.h"

#include <shlwapi.h>
#include <windows.h>

decltype(&CreateProcessW) OriginalCreateProcessW = nullptr;
decltype(&CreateWindowExW) OriginalCreateWindowExW = nullptr;

BOOL WINAPI HookedCreateProcessW(
	LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles,
	DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {

	auto passthrough = [&]() {
		return OriginalCreateProcessW(
			lpApplicationName, lpCommandLine, lpProcessAttributes,
			lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
			lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
	};

	WCHAR exePath[MAX_PATH]{};
	GetLaunchedExePath(lpApplicationName, lpCommandLine, exePath);
	if (exePath[0] && ShouldPassThrough(exePath, lpCurrentDirectory))
		return passthrough();

	LOG("CreateProcessW intercepted: %ls\n",
		lpCommandLine ? lpCommandLine : L"(null)");

	if (g_targetExe[0] && (!exePath[0] || !StrStrIW(PathFindFileNameW(exePath), g_targetExe))) {
		LOG("Exe does not match target '%ls', passing through\n", g_targetExe);
		return passthrough();
	}

	if (g_isLauncher) {
		LOG("CreateProcessW > launcher mode (skipping disabling dse)\n");
	} else if (g_config.toggleDse && !g_wasOffFromStart) {
		if (IsDseEnabledNtdll()) {
			LOG("CreateProcessW > disabling DSE\n");
			DisableDse();
		} else {
			LOG("CreateProcessW > DSE already disabled\n");
		}
	}

	BOOL ok = OriginalCreateProcessW(
		lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
		bInheritHandles, dwCreationFlags | CREATE_SUSPENDED, lpEnvironment,
		lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

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

	LOG("CreateProcessWithTokenW -> redirecting to CreateProcessW\n");
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

	static bool s_dseRestored = false;
	if (!s_dseRestored && g_config.toggleDse && !g_wasOffFromStart && !g_isLauncher && hwnd != nullptr) {
		s_dseRestored = true;
		if (g_wasToggled) {
			LOG("Window created > Disabled DSE earlier, restoring now...\n");
			EnableDse();
		} else {
			LOG("Window created > DSE was not disabled, skipping\n");
		}
	}
	return hwnd;
}
