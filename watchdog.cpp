#include "watchdog.h"

#include "common.h"
#include "config.h"
#include "drvloader.h"
#include "events.h"
#include "log.h"

#include <cstdlib>
#include <cstring>

static constexpr LPCWSTR kWatchdogCommandTemplate =
	L"rundll32.exe \"%s\",DseWatchdog %lu %s";

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

	char *drvStart = p;
	while (*p && *p != ' ' && *p != '\r' && *p != '\n')
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

	LOG("[WATCHDOG] PID=%ld\n", pid);
	LOG("[WATCHDOG] drvloader: %s\n", drvA);

	HANDLE hProc = OpenProcess(SYNCHRONIZE, FALSE, (DWORD)pid);
	if (!hProc) {
		LOG("[WATCHDOG] OpenProcess failed! err: %lu\n", GetLastError());
		return;
	}

	LOG("[WATCHDOG] Waiting for game to exit...\n");
	WaitForSingleObject(hProc, INFINITE);
	CloseHandle(hProc);
	LOG("[WATCHDOG] Game exited!\n");

	if (DseWasOffFromStart()) {
		LOG("[WATCHDOG] DSE was off from start, skipping restore.\n");
	} else {
		lstrcpynW(drvPath, drvPath, MAX_PATH);

		if (IsDseEnabled(false)) {
			LOG("[WATCHDOG] DSE already enabled, skipping.\n");
		} else {
			EnableDse();
			LOG("[WATCHDOG] Restoration complete.\n");
		}
	}

	DeleteDseOffFromStartLock();
	DeleteDseToggledLock();
	DeleteFileW(drvPath);
	LOG("[WATCHDOG] Exiting.\n");
	exit(0);
}

void SpawnWatchdog() {
	EnsureDrvExtracted();

	WCHAR dllPath[MAX_PATH]{};
	if (!GetModuleFileNameW(g_hModule, dllPath, MAX_PATH))
		return;

	WCHAR cmdLine[MAX_PATH * 4]{};
	wsprintfW(cmdLine, kWatchdogCommandTemplate, dllPath, GetCurrentProcessId(),
			  drvPath);

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
