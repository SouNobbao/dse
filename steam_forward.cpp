#pragma once
#include "config.h"
#include "log.h"
#include "hooks.h"
#include "hide_module.h"
#include <filesystem>
#include <windows.h>

static void HookSteamAPI(HMODULE hSteamApi);

static volatile LONG s_api_forward_state = 0; // 0 = not started, 1 = in progress, 2 = ready

static void SetupSteamApiForwarding(HMODULE hEmulator, bool rebindImports) {
	if (!hEmulator || InterlockedCompareExchange(&s_api_forward_state, 1, 0) != 0)
		return;

	WCHAR emuPath[MAX_PATH]{};
	GetModuleFileNameW(hEmulator, emuPath, MAX_PATH);
	LOG("steam_api64.dll emulator at %p: %ls\n", hEmulator, emuPath);

	std::error_code ec;
	const std::filesystem::path realPath =
		std::filesystem::path(emuPath).parent_path() / L"steam_api64_o.dll";
	if (!std::filesystem::exists(realPath, ec)) {
		LOG("steam_api64_o.dll not found next to the emulator: %ls\n",
			realPath.c_str());
		InterlockedExchange(&s_api_forward_state, 0);
		return;
	}

	HMODULE hReal = LoadLibraryExW(realPath.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
	if (!hReal) {
		LOG("Failed to load %ls: %lu\n", realPath.c_str(), GetLastError());
		InterlockedExchange(&s_api_forward_state, 0);
		return;
	}
	LOG("Real steam_api64 loaded at %p from %ls\n", hReal, realPath.c_str());

	const int forwarded = HookAllExports(hEmulator, hReal);

	if (forwarded > 0 && g_config.steamHooks)
		HookSteamAPI(hEmulator);

	const int rebound = rebindImports ? RebindImports("steam_api64.dll", hEmulator) : 0;
	LOG("steam_api64: %d exports forwarded, %d IAT entries rebound\n", forwarded, rebound);

	HideLdrEntry(hReal);
	InterlockedExchange(&s_api_forward_state, forwarded > 0 ? 2 : 0);
}

static bool IsSteamApi64Module(HMODULE hModule) {
	WCHAR path[MAX_PATH]{};
	return GetModuleFileNameW(hModule, path, MAX_PATH) &&
		   _wcsicmp(std::filesystem::path(path).filename().c_str(),
					L"steam_api64.dll") == 0;
}

typedef NTSTATUS(NTAPI *fnLdrLoadDll)(PWSTR, PULONG, PVOID, PVOID *);
static fnLdrLoadDll oLdrLoadDll = nullptr;

static NTSTATUS NTAPI hkLdrLoadDll(PWSTR searchPath, PULONG characteristics, PVOID dllName,
								   PVOID *dllHandle) {
	NTSTATUS status = oLdrLoadDll(searchPath, characteristics, dllName, dllHandle);
	if (status >= 0 && dllHandle && *dllHandle &&
		InterlockedCompareExchange(&s_api_forward_state, 0, 0) == 0 &&
		IsSteamApi64Module((HMODULE)*dllHandle))
		SetupSteamApiForwarding((HMODULE)*dllHandle, false);
	return status;
}

void InitSteamApiForward() {
	HMODULE hExisting = GetModuleHandleW(L"steam_api64.dll");
	if (hExisting) {
		LOG("steam_api64.dll already in memory at %p - setting up forwarding\n", hExisting);
		SetupSteamApiForwarding(hExisting, true);
		if (s_api_forward_state == 2)
			return;
	}

	void *pLdrLoadDll = (void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "LdrLoadDll");
	if (pLdrLoadDll && Hook(pLdrLoadDll, (void *)hkLdrLoadDll, (void **)&oLdrLoadDll))
		LOG("Hooked LdrLoadDll to intercept steam_api64.dll\n");
	else
		LOG("Failed to hook LdrLoadDll for steam_api64 forwarding\n");
}
