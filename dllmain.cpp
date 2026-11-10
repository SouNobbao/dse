#define WIN32_LEAN_AND_MEAN

#include "afterburner.h"
#include "common.h"
#include "config.h"
#include "dse_hooks.h"
#include "elevation.h"
#include "events.h"
#include "hide_module.h"
#include "hooks.h"
#include "launchers.h"
#include "log.h"
#include "minhook/include/MinHook.h"
#include "patcher.h"
#include "watchdog.h"

#include <windows.h>

HMODULE g_hModule = nullptr;
WCHAR g_targetExe[MAX_PATH] = {0};
bool g_wasOffFromStart = false;
bool g_wasToggled = false;
bool g_isLauncher = false;

extern "C" __declspec(dllexport) void DseDll(void) {}

extern "C" char *__cxa_demangle(const char *, char *, size_t *, int *status) {
	if (status) *status = -1;
	return nullptr;
}


#include "steam_hooks.cpp"
#include "steam_coldclient_hooks.cpp"
#include "steam_forward.cpp"

#include "checks.h"

static void InitializeHooks() {
	LOG("Initializing MinHook...\n");
	if (MH_Initialize() != MH_OK) {
		LOG("MinHook init failed!\n");
		return;
	}

	HookApi(L"kernel32.dll", "CreateProcessW",
			(LPVOID)&HookedCreateProcessW, (LPVOID *)&OriginalCreateProcessW);
	HookApi(L"user32.dll", "CreateWindowExW",
			(LPVOID)&HookedCreateWindowExW, (LPVOID *)&OriginalCreateWindowExW);
	HookApi(L"advapi32.dll", "CreateProcessWithTokenW",
			(LPVOID)&HookedCreateProcessWithTokenW, nullptr);

	LOG("Hooks installed\n");
}

static void PrepareDse() {
	WaitForWatchdogToExit();
	if (IsDseEnabledNtdll()) {
		LOG("Running as ADMIN, disabling DSE...\n");
		DisableDse();
		SetDseToggled();
		g_wasToggled = true;
	} else if (CheckAndSetDseToggled()) {
		LOG("DSE off (parent disabled it), proceeding normally\n");
		g_wasToggled = true;
	} else {
		LOG("DSE off from start (testsigning etc.)\n");
		SetDseOffFromStart();
		g_wasOffFromStart = true;
	}
}

static void OnProcessAttach(HMODULE hModule) {
	DisableThreadLibraryCalls(hModule);
	g_hModule = hModule;

	LoadDseConfig(hModule);
	g_loggingEnabled = g_config.logging;

	HideModule();

	if (IsHostPassthrough())
		return;

	SetupLogConsole(g_hModule);

	LOG("Attached to PID %lu\n", GetCurrentProcessId());
	LOG("Config: toggleDse=%d steamHooks=%d logging=%d\n",
		g_config.toggleDse, g_config.steamHooks, g_config.logging);

	if (g_config.toggleDse && !IsRunningAsAdmin())
		RelaunchElevatedAndExit();

	g_isLauncher = DetectLauncherTarget(g_targetExe, ARRAYSIZE(g_targetExe));
	if (g_config.toggleDse) {
		ManageProblematicServices();
		ManageProblematicTasks();
	}

	CheckAndSetAfterburnerEvent();
	if (g_config.toggleDse && IsAfterburnerRunning())
		SetAfterburnerRunningState(true);

	SystemChecks();

	if (g_config.toggleDse)
		PrepareDse();
	else
		LOG("DSE toggling disabled by config\n");

	InitializeHooks();
	if (g_config.steamHooks) {
		InitSteamHooks();
		if (g_config.coldloaderhooks)
			InitSteamColdHooks();
	} else {
		LOG("Steam hooks disabled by config\n");
	}
	if (g_config.steamApiForward)
		InitSteamApiForward();

	if (g_isLauncher)
		LOG("Launcher detected, skipping watchdog\n");
	else if (g_config.toggleDse)
		Watchdog::spawn(g_wasOffFromStart, g_wasToggled);
	else
		LOG("DSE toggling disabled, skipping watchdog\n");
}

static void OnProcessDetach() {
	if (IsHostPassthrough())
		return;

	LOG("Detaching...\n");
	CloseDseEvents();

	bool otherGameRunning = IsOtherGameRunning();

	if (g_config.toggleDse && !g_wasOffFromStart) {
		if (IsDseEnabledNtdll())
			LOG("Detaching > DSE already enabled, skipping\n");
		else if (otherGameRunning)
			LOG("Detaching > another game is running, skipping restore\n");
		else {
			LOG("Detaching... restoring DSE...\n");
			EnableDse();
		}
	}

	if (g_config.toggleDse && !otherGameRunning)
		RestoreProblematicServices();

	FreeDseConfig();

	LOG("Uninitializing MinHook...\n");
	MH_Uninitialize();
	LOG("Detached!\n");
	CloseLog();
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
