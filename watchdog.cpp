#include "watchdog.h"

#include "checks.h"
#include "common.h"
#include "config.h"
#include "events.h"
#include "log.h"
#include "patcher.h"

#include <shlwapi.h>

static constexpr LPCWSTR kWatchdogCommandTemplate =
	L"rundll32.exe \"%s\",DseWatchdog %lu %d %d %s";

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

	char *p = lpszCmdLine;
	char *end = nullptr;

	long pid = strtol(p, &end, 10);
	if (end == p || *end != ' ') {
		LOG("[WATCHDOG] Bad PID\n");
		return;
	}
	p = end + 1;

	long wasOffFromStart = strtol(p, &end, 10);
	if (end == p || *end != ' ') {
		LOG("[WATCHDOG] Bad wasOffFromStart\n");
		return;
	}
	p = end + 1;

	long wasToggled = strtol(p, &end, 10);
	if (end == p || *end != ' ') {
		LOG("[WATCHDOG] Bad wasToggled\n");
		return;
	}
	p = end + 1;

	char *drvStart = p;
	while (*p && *p != '\r' && *p != '\n')
		p++;
	char drvA[MAX_PATH] = {0};
	int drvLen = (int)(p - drvStart);
	if (drvLen <= 0 || drvLen >= MAX_PATH) {
		LOG("[WATCHDOG] Bad drvPath\n");
		return;
	}
	memcpy(drvA, drvStart, drvLen);

	WCHAR drvPath[MAX_PATH] = {0};
	MultiByteToWideChar(CP_ACP, 0, drvA, -1, drvPath, MAX_PATH);

	LOG("[WATCHDOG] PID=%ld, wasOffFromStart=%ld, wasToggled=%ld\n", pid, wasOffFromStart, wasToggled);
	LOG("[WATCHDOG] drvloader: %s\n", drvA);

	// Grab handles to global events so they stay alive even if the game crashes
	if (wasToggled) {
		CheckAndSetDseToggled();
	}
	if (wasOffFromStart) {
		CheckAndSetDseOffFromStart();
	}
	CheckAndSetAfterburnerEvent();

	HANDLE hWatchdogMutex = CreateMutexW(nullptr, TRUE, L"Local\\DseDll_WatchdogAlive");

	HANDLE hProc = OpenProcess(SYNCHRONIZE, FALSE, (DWORD)pid);
	if (!hProc) {
		LOG("[WATCHDOG] OpenProcess failed! err: %lu\n", GetLastError());
		if (hWatchdogMutex) CloseHandle(hWatchdogMutex);
		return;
	}

	LOG("[WATCHDOG] Waiting for game to exit...\n");
	WaitForSingleObject(hProc, INFINITE);
	CloseHandle(hProc);

	LOG("[WATCHDOG] Game exited!\n");

	if (wasOffFromStart) {
		LOG("[WATCHDOG] DSE was off from start, skipping restore.\n");
	} else {
		CloseGameEvents();

		if (IsOtherGameRunning()) {
			LOG("[WATCHDOG] Another game is still running, skipping restore.\n");
		} else {
			lstrcpynW(drvPath, drvPath, MAX_PATH);

			if (IsDseEnabled(false)) {
				LOG("[WATCHDOG] DSE already enabled, skipping.\n");
			} else {
				EnableDse();
				LOG("[WATCHDOG] Restoration complete.\n");
			}

			if (g_config.toggleDse) {
				RestoreProblematicServices();
			}
		}
	}

	CloseDseEvents();
	DeleteFileW(drvPath);
	if (hWatchdogMutex) CloseHandle(hWatchdogMutex);
	LOG("[WATCHDOG] Exiting.\n");
	exit(0);
}

void SpawnWatchdog(bool wasOffFromStart, bool wasToggled) {
	WCHAR hostPath[MAX_PATH]{};
	if (GetModuleFileNameW(nullptr, hostPath, MAX_PATH) && IsPassthroughExe(PathFindFileNameW(hostPath))) {
		return;
	}

	EnsurePatcherExtracted();

	WCHAR dllPath[MAX_PATH]{};
	if (!GetModuleFileNameW(g_hModule, dllPath, MAX_PATH))
		return;

	WCHAR cmdLine[MAX_PATH * 4]{};
	wsprintfW(cmdLine, kWatchdogCommandTemplate, dllPath, GetCurrentProcessId(),
			  wasOffFromStart ? 1 : 0, wasToggled ? 1 : 0, patcherPath);

	LOG("[DSE-DLL] Spawning watchdog: %ls\n", cmdLine);

	STARTUPINFOW si = {sizeof(si)};
	PROCESS_INFORMATION pi{};
	if (CreateProcessW(nullptr, cmdLine, nullptr, nullptr, FALSE,
					   CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	} else {
		LOG("[DSE-DLL] Failed to spawn watchdog, err: %lu\n", GetLastError());
	}
}
