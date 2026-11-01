#include "watchdog.h"

#include "checks.h"
#include "common.h"
#include "config.h"
#include "events.h"
#include "log.h"
#include "patcher.h"

#include <cstdio>
#include <shlwapi.h>

// Args: inherited game process handle, wasOffFromStart, wasToggled.
static constexpr LPCWSTR kWatchdogCommandTemplate =
	L"rundll32.exe \"%s\",DseWatchdog %lu %d %d";

static void RestoreDseIfNeeded(bool wasOffFromStart) {
	if (wasOffFromStart) {
		LOG("[WATCHDOG] DSE was off from start, skipping restore.\n");
		return;
	}
	CloseGameEvents();
	if (IsOtherGameRunning()) {
		LOG("[WATCHDOG] Another game is still running, skipping restore.\n");
		return;
	}
	if (IsDseEnabled(false)) {
		LOG("[WATCHDOG] DSE already enabled, skipping.\n");
	} else {
		EnableDse();
		LOG("[WATCHDOG] Restoration complete.\n");
	}
	if (g_config.toggleDse)
		RestoreProblematicServices();
}

extern "C" __declspec(dllexport) void CALLBACK DseWatchdog(HWND hwnd,
														   HINSTANCE hinst,
														   LPSTR lpszCmdLine,
														   int nCmdShow) {
	(void)hwnd;
	(void)hinst;
	(void)nCmdShow;

	InitLogPath(g_hModule);
	LoadDseConfig(g_hModule);
	g_loggingEnabled = g_config.logging;
	LOG("[WATCHDOG] Started with args: %s\n", lpszCmdLine);

	unsigned long gameHandle = 0;
	int wasOffFromStart = 0, wasToggled = 0;
	if (sscanf_s(lpszCmdLine, "%lu %d %d", &gameHandle, &wasOffFromStart, &wasToggled) != 3) {
		LOG("[WATCHDOG] Bad args\n");
		return;
	}
	// Kernel handles are guaranteed to fit in 32 bits, so the round trip is lossless.
	HANDLE hGame = (HANDLE)(ULONG_PTR)gameHandle;

	if (wasToggled)
		CheckAndSetDseToggled();
	if (wasOffFromStart)
		CheckAndSetDseOffFromStart();
	CheckAndSetAfterburnerEvent();

	HANDLE hWatchdogMutex = CreateMutexW(nullptr, TRUE, L"Local\\DseDll_WatchdogAlive");

	LOG("[WATCHDOG] Waiting for game to exit...\n");
	// On failure, restore anyway: leaving DSE off is worse than restoring early.
	if (WaitForSingleObject(hGame, INFINITE) == WAIT_FAILED)
		LOG("[WATCHDOG] Wait failed, err: %lu, restoring now\n", GetLastError());
	else
		LOG("[WATCHDOG] Game exited!\n");
	CloseHandle(hGame);

	RestoreDseIfNeeded(wasOffFromStart != 0);

	CloseDseEvents();
	DeletePatcherFile();
	if (hWatchdogMutex)
		CloseHandle(hWatchdogMutex);
	LOG("[WATCHDOG] Exiting.\n");
	exit(0);
}

void SpawnWatchdog(bool wasOffFromStart, bool wasToggled) {
	if (IsHostPassthrough())
		return;

	WCHAR dllPath[MAX_PATH]{};
	if (!GetModuleFileNameW(g_hModule, dllPath, MAX_PATH))
		return;

	// The watchdog waits on this handle instead of a PID, so it can't miss a fast
	// exit or end up waiting on a reused PID.
	HANDLE hSelf = nullptr;
	if (!DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(),
						 &hSelf, SYNCHRONIZE, TRUE, 0)) {
		LOG("[DSE-DLL] Failed to duplicate game handle, err: %lu\n", GetLastError());
		return;
	}

	WCHAR cmdLine[MAX_PATH * 4]{};
	wsprintfW(cmdLine, kWatchdogCommandTemplate, dllPath, (DWORD)(ULONG_PTR)hSelf,
			  wasOffFromStart ? 1 : 0, wasToggled ? 1 : 0);
	LOG("[DSE-DLL] Spawning watchdog: %ls\n", cmdLine);

	// Inherit only hSelf; the game's other inheritable handles (e.g. launcher
	// stdout pipes) would otherwise stay open for the watchdog's lifetime.
	SIZE_T attrSize = 0;
	InitializeProcThreadAttributeList(nullptr, 1, 0, &attrSize);
	auto attrs = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
	bool attrsReady = attrs && InitializeProcThreadAttributeList(attrs, 1, 0, &attrSize);

	STARTUPINFOEXW si{};
	si.StartupInfo.cb = sizeof(si);
	si.lpAttributeList = attrs;
	PROCESS_INFORMATION pi{};
	bool ok = attrsReady &&
			  UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
										&hSelf, sizeof(hSelf), nullptr, nullptr) &&
			  CreateProcessW(nullptr, cmdLine, nullptr, nullptr, TRUE,
							 CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
							 nullptr, nullptr, &si.StartupInfo, &pi);
	if (ok) {
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	} else {
		LOG("[DSE-DLL] Failed to spawn watchdog, err: %lu\n", GetLastError());
	}

	if (attrsReady)
		DeleteProcThreadAttributeList(attrs);
	if (attrs)
		HeapFree(GetProcessHeap(), 0, attrs);
	CloseHandle(hSelf);
}
