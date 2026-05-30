#include <cstdlib>
#define WIN32_LEAN_AND_MEAN

#include "afterburner.h"
#include "common.h"
#include "config.h"
#include "events.h"
#include "injector.h"
#include "launchers.h"
#include "log.h"
#include "minhook/include/MinHook.h"
#include "patcher.h"
#include "watchdog.h"
#include "hide_module.h"

#include <cstring>
#include <shellapi.h>
#include <shlwapi.h>
#include <windows.h>

#pragma comment(lib, "shlwapi.lib")

static WCHAR g_targetExe[MAX_PATH] = {0};
static bool g_wasOffFromStart = false;
static bool g_wasToggled = false;

extern "C" __declspec(dllexport) void DseDll(void) {}

HMODULE g_hModule = nullptr;

#include "steam_hooks.cpp"

static bool IsRundll32Host() {
	WCHAR hostExe[MAX_PATH]{};
	GetModuleFileNameW(nullptr, hostExe, MAX_PATH);
	return StrStrIW(PathFindFileNameW(hostExe), L"rundll32") != nullptr;
}

#include "checks.h"

static constexpr LPCWSTR kWscriptCommandTemplate =
	L"wscript.exe //nologo \"%s\"";

static void RelaunchElevatedAndExit() {
	LOG("[DSE-DLL] Not admin elevating ...\n");

	WCHAR exePath[MAX_PATH]{};
	GetModuleFileNameW(nullptr, exePath, MAX_PATH);

	LPCWSTR cmdArgs = PathGetArgsW(GetCommandLineW());

	WCHAR workDir[MAX_PATH]{};
	GetModuleFileNameW(nullptr, workDir, MAX_PATH);
	PathRemoveFileSpecW(workDir);

	WCHAR vbsPath[MAX_PATH]{};
	GetTempPathW(MAX_PATH, vbsPath);
	PathAppendW(vbsPath, kElevationScriptName);

	WCHAR vbsContent[4096]{};
	wsprintfW(vbsContent, kElevationVbsTemplate, exePath, cmdArgs, workDir);

	HANDLE hVbs = CreateFileW(vbsPath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
							  FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hVbs != INVALID_HANDLE_VALUE) {
		WORD bom = 0xFEFF;
		DWORD written = 0;
		WriteFile(hVbs, &bom, sizeof(bom), &written, nullptr);
		WriteFile(hVbs, vbsContent, lstrlenW(vbsContent) * sizeof(WCHAR), &written,
				  nullptr);
		CloseHandle(hVbs);
	}

	WCHAR wscriptCmd[MAX_PATH * 2]{};
	wsprintfW(wscriptCmd, kWscriptCommandTemplate, vbsPath);

	LOG("[DSE-DLL] Running: %ls\n", wscriptCmd);

	STARTUPINFOW si = {sizeof(si)};
	PROCESS_INFORMATION pi{};

	if (CreateProcessW(nullptr, wscriptCmd, nullptr, nullptr, FALSE, 0, nullptr,
					   workDir, &si, &pi)) {
		LOG("[DSE-DLL] vbscript launched, waiting for elevation...\n");
		WaitForSingleObject(pi.hProcess, 15000);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		LOG("[DSE-DLL] Terminating non-admin instance.\n");
	}

	DeleteFileW(vbsPath);
	ExitProcess(0);
}

pCreateProcessW_t OriginalCreateProcessW = nullptr;

typedef HWND(WINAPI *pCreateWindowExW)(DWORD, LPCWSTR, LPCWSTR, DWORD, int, int,
									   int, int, HWND, HMENU, HINSTANCE,
									   LPVOID);
static pCreateWindowExW OriginalCreateWindowExW = nullptr;

typedef BOOL(WINAPI *pCreateProcessWithTokenW)(HANDLE, DWORD, LPCWSTR, LPWSTR,
											   DWORD, LPVOID, LPCWSTR,
											   LPSTARTUPINFOW,
											   LPPROCESS_INFORMATION);
static pCreateProcessWithTokenW OriginalCreateProcessWithTokenW = nullptr;

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

	static WCHAR s_gameDir[MAX_PATH]{};
	if (GetModuleFileNameW(nullptr, s_gameDir, MAX_PATH)) {
		PathRemoveFileSpecW(s_gameDir);
		PathAddBackslashW(s_gameDir);
	}

	auto cmdLineToExePath = [](LPCWSTR cmdLine, WCHAR *out, int outLen) {
		out[0] = L'\0';
		if (!cmdLine || !cmdLine[0])
			return;
		int argc = 0;
		LPWSTR *argv = CommandLineToArgvW(cmdLine, &argc);
		if (argv) {
			if (argc > 0)
				wcsncpy_s(out, outLen, argv[0], _TRUNCATE);
			LocalFree(argv);
		}
	};

	WCHAR exePath[MAX_PATH]{};
	if (lpApplicationName && lpApplicationName[0])
		lstrcpynW(exePath, lpApplicationName, MAX_PATH);
	else if (lpCommandLine)
		cmdLineToExePath(lpCommandLine, exePath, MAX_PATH);

	if (exePath[0]) {
		WCHAR resolvedPath[MAX_PATH]{};
		if (PathIsRelativeW(exePath)) {
			WCHAR cwd[MAX_PATH]{};
			const WCHAR *base =
				(lpCurrentDirectory && lpCurrentDirectory[0]) ? lpCurrentDirectory
				: GetCurrentDirectoryW(MAX_PATH, cwd)		  ? cwd
															  : nullptr;
			if (base)
				PathCombineW(resolvedPath, base, exePath);
		} else {
			lstrcpynW(resolvedPath, exePath, MAX_PATH);
		}

		const WCHAR *checkPath = resolvedPath[0] ? resolvedPath : exePath;

		if (s_gameDir[0] && StrStrIW(checkPath, s_gameDir) != checkPath)
			return passthrough();

		LPCWSTR exeName = PathFindFileNameW(exePath);
		if (StrStrIW(exeName, L"drvloader") || StrStrIW(exeName, L"crash") ||
			StrStrIW(exeName, L"watchdog") || StrStrIW(exeName, L"rundll32"))
			return passthrough();
	}

	LOG("[DSE-DLL] CreateProcessW intercepted: %ls\n",
		lpCommandLine ? lpCommandLine : L"(null)");

	if (g_targetExe[0]) {
		LPCWSTR exeName = exePath[0] ? PathFindFileNameW(exePath) : nullptr;
		if (!exeName || !StrStrIW(exeName, g_targetExe)) {
			LOG("[DSE-DLL] Exe does not match target '%ls', passing through\n",
				g_targetExe);
			return passthrough();
		}
	}

	if (g_config.toggleDse && !g_wasOffFromStart) {
		if (IsDseEnabledNtdll()) {
			LOG("[DSE-DLL] CreateProcessW > disabling DSE\n");
			DisableDse();
		} else {
			LOG("[DSE-DLL] CreateProcessW > DSE already disabled\n");
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

	LOG("[DSE-DLL] CreateProcessWithTokenW -> redirecting to CreateProcessW\n");
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
	if (!s_dseRestored && g_config.toggleDse && !g_wasOffFromStart && hwnd != nullptr) {
		s_dseRestored = true;
		if (g_wasToggled) {
			LOG("[DSE-DLL] Window created > we disabled DSE earlier, restoring now...\n");
			EnableDse();
		} else {
			LOG("[DSE-DLL] Window created > DSE wasn't disabled by us, skipping\n");
		}
	}
	return hwnd;
}

static void InitializeHooks() {
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

	MH_CreateHookApi(L"advapi32.dll", "CreateProcessWithTokenW",
					 (LPVOID)&HookedCreateProcessWithTokenW,
					 (LPVOID *)&OriginalCreateProcessWithTokenW);

	MH_EnableHook(MH_ALL_HOOKS);
	LOG("[DSE-DLL] Hooks installed\n");
}

static void OnProcessAttach(HMODULE hModule) {
	DisableThreadLibraryCalls(hModule);
	g_hModule = hModule;

	if (IsRundll32Host())
		return;

	HideModule();

	LoadDseConfig(hModule);
	g_loggingEnabled = g_config.logging;

	SetupLogConsole(g_hModule);
	LOG("[DSE-DLL] Attached to PID %lu\n", GetCurrentProcessId());
	LOG("[DSE-DLL] Config: toggleDse=%d steamHooks=%d "
		"logging=%d\n",
		g_config.toggleDse, g_config.steamHooks,
		g_config.logging);

	if (g_config.toggleDse) {
		ManageProblematicServices();
		ManageProblematicTasks();
	}

	CheckAndSetAfterburnerEvent();

	if (g_config.toggleDse && IsAfterburnerRunning()) {
		SetAfterburnerRunningState(true);
	}

	DetectLauncherTarget(g_targetExe, ARRAYSIZE(g_targetExe));

	if (g_config.toggleDse && !IsRunningAsAdmin()) {
		RelaunchElevatedAndExit();
	} else {
		SystemChecks();

		if (g_config.toggleDse) {
			if (!IsDseEnabledNtdll()) {
				if (CheckAndSetDseToggled()) {
					LOG("[DSE-DLL] DSE off (parent disabled it), proceeding normally\n");
					g_wasToggled = true;
				} else {
					LOG("[DSE-DLL] DSE off from start (testsigning etc.)\n");
					SetDseOffFromStart();
					g_wasOffFromStart = true;
				}
			} else {
				LOG("[DSE-DLL] Running as ADMIN, disabling DSE...\n");
				DisableDse();
				SetDseToggled();
				g_wasToggled = true;
			}
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
	} else if (g_config.toggleDse) {
		SpawnWatchdog(g_wasOffFromStart, g_wasToggled);
	} else {
		LOG("[DSE-DLL] DSE toggling disabled, skipping watchdog\n");
	}
}

static void OnProcessDetach() {
	if (IsRundll32Host())
		return;

	LOG("[DSE-DLL] Detaching...\n");
	CloseDseEvents();

	bool otherGameRunning = IsOtherGameRunning();

	if (g_config.toggleDse && !g_wasOffFromStart) {
		if (IsDseEnabledNtdll()) {
			LOG("[DSE-DLL] Detaching > DSE already enabled, skipping\n");
		} else {
			if (otherGameRunning) {
				LOG("[DSE-DLL] Detaching > another game is running, skipping restore\n");
			} else {
				LOG("[DSE-DLL] Detaching... restoring DSE...\n");
				EnableDse();
			}
		}
	}

	if (g_config.toggleDse && !otherGameRunning) {
		RestoreProblematicServices();
	}
	LOG("[DSE-DLL] Uninitializing MinHook...\n");
	MH_Uninitialize();
	LOG("[DSE-DLL] Deleting patcher...\n");
	DeletePatcherFile();
	LOG("[DSE-DLL] Detached!\n");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call,
					  LPVOID lpReserved) {
	(void)lpReserved;

	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
		OnProcessAttach(hModule);
	else if (ul_reason_for_call == DLL_PROCESS_DETACH)
		OnProcessDetach();

	return TRUE;
}
