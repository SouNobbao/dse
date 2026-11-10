#include "watchdog.h"

#include "checks.h"
#include "common.h"
#include "config.h"
#include "events.h"
#include "log.h"
#include "patcher.h"

#include <shlwapi.h>

namespace Watchdog {
namespace {

constexpr LPCWSTR kCommandTemplate =
	L"rundll32.exe \"%s\",DseWatchdog %lu %d %d";

void RestoreDseIfNeeded(bool wasOffFromStart) {
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

} // anonymous namespace

void run(HWND hwnd,
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
	int wasOffFromStart = 0;
	int wasToggled = 0;

	if (sscanf_s(lpszCmdLine, "%lu %d %d", &gameHandle, &wasOffFromStart, &wasToggled) != 3) {
		LOG("[WATCHDOG] Bad args\n");
		return;
	}

	// Kernel handles are guaranteed to fit in 32 bits; the round-trip is lossless.
	HANDLE hGame = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(gameHandle));

	if (wasToggled)
		CheckAndSetDseToggled();
	if (wasOffFromStart)
		CheckAndSetDseOffFromStart();
	CheckAndSetAfterburnerEvent();

	HANDLE hWatchdogMutex = CreateMutexW(nullptr, TRUE, L"Local\\DseDll_WatchdogAlive");

	LOG("[WATCHDOG] Waiting for game to exit...\n");

	// On failure we still restore: leaving DSE disabled is worse than restoring early.
	const DWORD waitResult = WaitForSingleObject(hGame, INFINITE);
	if (waitResult == WAIT_FAILED)
		LOG("[WATCHDOG] Wait failed, err: %lu, restoring now\n", GetLastError());
	else
		LOG("[WATCHDOG] Game exited!\n");

	CloseHandle(hGame);

	RestoreDseIfNeeded(wasOffFromStart != 0);

	CloseDseEvents();
	if (hWatchdogMutex)
		CloseHandle(hWatchdogMutex);

	LOG("[WATCHDOG] Exiting.\n");
	exit(0);
}

void spawn(bool wasOffFromStart, bool wasToggled) {
	if (IsHostPassthrough())
		return;

	WCHAR dllPath[MAX_PATH]{};
	if (!GetModuleFileNameW(g_hModule, dllPath, MAX_PATH))
		return;

	HANDLE hSelf = nullptr;
	if (!DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(),
						 &hSelf, SYNCHRONIZE, TRUE, 0)) {
		LOG("Failed to duplicate game handle, err: %lu\n", GetLastError());
		return;
	}

	WCHAR cmdLine[MAX_PATH * 4]{};
	wsprintfW(cmdLine, kCommandTemplate, dllPath,
			  static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(hSelf)),
			  wasOffFromStart ? 1 : 0,
			  wasToggled ? 1 : 0);

	LOG("Spawning watchdog: %ls\n", cmdLine);

	SIZE_T attrSize = 0;
	InitializeProcThreadAttributeList(nullptr, 1, 0, &attrSize);

	auto* attrs = static_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(
		HeapAlloc(GetProcessHeap(), 0, attrSize));

	bool attrsReady = attrs &&
					  InitializeProcThreadAttributeList(attrs, 1, 0, &attrSize);

	STARTUPINFOEXW si{ sizeof(si) };
	si.lpAttributeList = attrs;

	PROCESS_INFORMATION pi{};

	const bool ok = attrsReady &&
					UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
											  &hSelf, sizeof(hSelf), nullptr, nullptr) &&
					CreateProcessW(nullptr, cmdLine, nullptr, nullptr, TRUE,
								   CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
								   nullptr, nullptr, &si.StartupInfo, &pi);

	if (ok) {
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	} else {
		LOG("Failed to spawn watchdog, err: %lu\n", GetLastError());
	}

	if (attrsReady)
		DeleteProcThreadAttributeList(attrs);
	if (attrs)
		HeapFree(GetProcessHeap(), 0, attrs);

	CloseHandle(hSelf);
}

} // namespace watchdog

extern "C" __declspec(dllexport) void CALLBACK DseWatchdog(HWND hwnd,
														   HINSTANCE hinst,
														   LPSTR lpszCmdLine,
														   int nCmdShow) {
	Watchdog::run(hwnd, hinst, lpszCmdLine, nCmdShow);
}
