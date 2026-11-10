#pragma once
#include "config.h"
#include "log.h"
#include "hooks.h"
#include "hide_module.h"
#include "minhook/include/MinHook.h"
#include "peb_struct.h"
#include <filesystem>
#include <shlwapi.h>
#include <windows.h>

// Interface hooking lives in steam_hooks.cpp. This file forwards the emulator's
// exports to the real client and hooks the real client's interfaces at load
// time; it keeps no code of its own in the forwarding path.
static void HookInterface_ISteamClient(void *pInterface, const char *pszVersion);
static void LoadSteamConfigFromDll(HMODULE hSteamApi);

static HMODULE g_hEmulatorClient = nullptr;
static HMODULE g_hRealSteamClient = nullptr;

static bool GetConfiguredSteamDir(std::filesystem::path &steamDir) {
	if (g_config.coldloaderhooks && !g_config.steam_path.empty()) {
		steamDir = g_config.steam_path;
		return true;
	}

	WCHAR regPath[MAX_PATH]{};
	DWORD size = ARRAYSIZE(regPath);
	if (RegGetValueW(HKEY_CURRENT_USER, L"Software\\Valve\\Steam",
					 L"SteamPath", RRF_RT_REG_SZ, nullptr, regPath,
					 &size) == ERROR_SUCCESS &&
		regPath[0]) {
		steamDir = regPath;
		return true;
	}

	size = ARRAYSIZE(regPath);
	if (RegGetValueW(HKEY_LOCAL_MACHINE, L"Software\\Valve\\Steam",
					 L"InstallPath", RRF_RT_REG_SZ, nullptr, regPath,
					 &size) == ERROR_SUCCESS &&
		regPath[0]) {
		steamDir = regPath;
		return true;
	}

	LOG("Cannot find Steam install path in registry\n");
	return false;
}

typedef HMODULE(WINAPI *fnLoadLibraryExW)(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
static fnLoadLibraryExW oLoadLibraryExW = nullptr;

static volatile LONG s_steam_hook_state = 0; // 0 = not started, 1 = in progress, 2 = ready

// Obtain the real client's own interfaces and hook them.
//
// Resolved straight out of the real module, never through the emulator, so this
// adds nothing to the forwarding path: the emulator's export table still points
// only at real steamclient64.
//
// Returns the number of client interfaces hooked.
static int HookRealClientInterfaces(HMODULE hReal) {
	if (!hReal)
		return 0;

	typedef void *(*tCreateInterface)(const char *pName, int *pReturnCode);
	tCreateInterface realCreateInterface =
		reinterpret_cast<tCreateInterface>((void *)GetProcAddress(hReal, "CreateInterface"));
	if (!realCreateInterface) {
		LOG("Real client exports no CreateInterface; interfaces left unhooked\n");
		return 0;
	}

	// Steam keeps one client object per version, and the game may ask for any of
	// them, so hook every one it offers rather than guessing which it wants.
	static const char *const kClientVersions[] = {"SteamClient021", "SteamClient020",
												  "SteamClient019", "SteamClient018",
												  "SteamClient017", "SteamClient016",
												  "SteamClient015", "SteamClient014",
												  nullptr};

	int hooked = 0;
	for (int i = 0; kClientVersions[i]; ++i) {
		int code = 0;
		void *client = realCreateInterface(kClientVersions[i], &code);
		if (!client)
			continue;
		LOG("Pre-hooking real ISteamClient via %s @ %p\n", kClientVersions[i],
			client);
		HookInterface_ISteamClient(client, kClientVersions[i]);
		++hooked;
	}

	if (hooked == 0)
		LOG("Real client returned no ISteamClient; interfaces left unhooked\n");
	return hooked;
}

static bool PrepareRealClientAlias(const std::filesystem::path &steamDir,
								   const std::filesystem::path &realPath,
								   std::filesystem::path &aliasPath,
								   bool *outAliasCreated) {
	*outAliasCreated = false;
	aliasPath = steamDir / L"steamclient64_valve.dll";

	std::error_code ec;
	if (std::filesystem::exists(aliasPath, ec)) {
		LOG("Reusing existing real Steam DLL alias: %ls\n", aliasPath.c_str());
		return true;
	}

	if (!CreateHardLinkW(aliasPath.c_str(), realPath.c_str(), nullptr)) {
		LOG("Failed to create hard link for real Steam DLL: %lu\n",
			GetLastError());
		if (!CopyFileW(realPath.c_str(), aliasPath.c_str(), FALSE)) {
			LOG("Fallback copy also failed: %lu\n", GetLastError());
			return false;
		}
	}
	*outAliasCreated = true;
	return true;
}

// Runs from inside the game's own LoadLibraryExW for steamclient64, before the
// game can call into it, so the interfaces are hooked before first use.
//
// At most one attempt runs at a time, gated by s_steam_hook_state. A failed
// attempt resets the state so a later load can retry.
static void SetupSteamClientForwarding(HMODULE hEmulator) {
	if (!hEmulator)
		return;
	if (InterlockedCompareExchange(&s_steam_hook_state, 1, 0) != 0)
		return;

	static const LPCWSTR kDllName = L"steamclient64.dll";
	g_hEmulatorClient = hEmulator;

	WCHAR loadedPath[MAX_PATH]{};
	GetModuleFileNameW(hEmulator, loadedPath, MAX_PATH);
	LOG("%ls emulator loaded at %p\n", kDllName, hEmulator);
	LOG("Steam emulator path: %ls\n", loadedPath);

	LoadSteamConfigFromDll(hEmulator);

	// Publishes the outcome and releases the state lock. Every failure below
	// funnels through here rather than through scattered early returns.
	auto finish = [](bool ok) {
		InterlockedExchange(&s_steam_hook_state, ok ? 2 : 0);
		if (!ok) {
			g_hRealSteamClient = nullptr;
			LOG("Steam client forwarding setup did not complete; will retry on next load\n");
		}
	};

	const fnLoadLibraryExW loadLibraryExW = oLoadLibraryExW
												? oLoadLibraryExW
												: (fnLoadLibraryExW)&LoadLibraryExW;

	// Locates the real client, loads it under an alias name, forwards the
	// emulator's exports onto it, then hooks the real client's interfaces.
	auto setup = [&]() -> bool {
		std::filesystem::path steamDir;
		if (!GetConfiguredSteamDir(steamDir))
			return false;

		const std::filesystem::path realPath = steamDir / kDllName;
		std::error_code ec;
		if (!std::filesystem::exists(realPath, ec)) {
			LOG("Steam %ls not found: %ls\n", kDllName, realPath.c_str());
			return false;
		}
		LOG("Steam %ls: %ls\n", kDllName, realPath.c_str());

		std::filesystem::path aliasPath;
		bool aliasCreated = false;
		if (!PrepareRealClientAlias(steamDir, realPath, aliasPath, &aliasCreated))
			return false;

		HMODULE hReal = loadLibraryExW(aliasPath.c_str(), nullptr,
									   LOAD_WITH_ALTERED_SEARCH_PATH);
		if (!hReal) {
			LOG("Failed to load temp Steam DLL: %lu\n", GetLastError());
			return false;
		}
		LOG("Steam loaded at %p from %ls\n", hReal, aliasPath.c_str());

		// Drop the alias once nothing holds it, so the Steam directory is left
		// the way we found it.
		if (aliasCreated && !MoveFileExW(aliasPath.c_str(), nullptr,
										 MOVEFILE_DELAY_UNTIL_REBOOT))
			LOG("Could not schedule Steam DLL alias cleanup: %lu\n",
				GetLastError());

		g_hRealSteamClient = hReal;

		const int forwarded = HookAllExports(hEmulator, hReal);
		if (forwarded > 0) {
			LOG("%d emulator exports now forwarding to real %ls\n", forwarded,
				kDllName);
		} else {
			LOG("No exports hooked for %ls!\n", kDllName);
		}

		HookRealClientInterfaces(hReal);

		HideLdrEntry(hReal);
		return forwarded > 0;
	};

	finish(setup());
}

static HMODULE WINAPI hkLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
	LPCWSTR targetPath = lpLibFileName;

	const bool isSteamClient = lpLibFileName && StrStrIW(lpLibFileName, L"steamclient64.dll");
	const bool isOverlay = lpLibFileName && StrStrIW(lpLibFileName, L"gameoverlayrenderer64.dll");

	static bool s_overlay_hooked = false;
	static std::filesystem::path overlayRealPath;

	if (isOverlay && !s_overlay_hooked) {
		if (overlayRealPath.empty()) {
			std::filesystem::path steamDir;
			if (GetConfiguredSteamDir(steamDir))
				overlayRealPath = steamDir / L"gameoverlayrenderer64.dll";
		}

		std::error_code ec;
		if (!overlayRealPath.empty() && std::filesystem::exists(overlayRealPath, ec)) {
			targetPath = overlayRealPath.c_str();
			dwFlags |= LOAD_WITH_ALTERED_SEARCH_PATH;
			s_overlay_hooked = true;
			LOG("Redirecting gameoverlayrenderer64.dll to valve : %ls\n", targetPath);
		}
	}

	HMODULE hModule = oLoadLibraryExW(targetPath, hFile, dwFlags);

	if (hModule && isSteamClient &&
		InterlockedCompareExchange(&s_steam_hook_state, 0, 0) == 0) {
		SetupSteamClientForwarding(hModule);
	}
	return hModule;
}

typedef FARPROC(WINAPI *fnGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
static fnGetProcAddress oGetProcAddress = nullptr;

static FARPROC WINAPI hkGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
	FARPROC proc = oGetProcAddress(hModule, lpProcName);
	if (proc || !hModule || hModule != g_hEmulatorClient || !g_hRealSteamClient)
		return proc;

	proc = oGetProcAddress(g_hRealSteamClient, lpProcName);
	if (proc && ((ULONG_PTR)lpProcName > 0xFFFF))
		LOG("GetProcAddress forwarded %s to real steamclient\n", lpProcName);
	return proc;
}

void InitSteamColdHooks() {
	HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
	HMODULE hKernelBase = GetModuleHandleW(L"kernelbase.dll");
	void *pLoadLib = nullptr;
	if (hKernelBase)
		pLoadLib = (void *)GetProcAddress(hKernelBase, "LoadLibraryExW");
	if (!pLoadLib && hKernel32)
		pLoadLib = (void *)GetProcAddress(hKernel32, "LoadLibraryExW");

	if (pLoadLib) {
		Hook(pLoadLib, (void *)hkLoadLibraryExW, (void **)&oLoadLibraryExW);
		LOG("Hooked LoadLibraryExW to intercept steamclient64.dll\n");
	}

	void *pGetProcAddr = nullptr;
	if (hKernelBase)
		pGetProcAddr = (void *)GetProcAddress(hKernelBase, "GetProcAddress");
	if (!pGetProcAddr && hKernel32)
		pGetProcAddr = (void *)GetProcAddress(hKernel32, "GetProcAddress");

	if (pGetProcAddr) {
		Hook(pGetProcAddr, (void *)hkGetProcAddress, (void **)&oGetProcAddress);
		LOG("Hooked GetProcAddress for steamclient internal exports\n");
	}

	HMODULE hExistingClient = GetModuleHandleW(L"steamclient64.dll");
	if (hExistingClient) {
		LOG("steamclient64.dll already in memory at %p - setting up forwarding\n", hExistingClient);
		SetupSteamClientForwarding(hExistingClient);
	}
}
