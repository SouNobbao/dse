#include "config.h"
#include "events.h"
#include "log.h"
#define WIN32_LEAN_AND_MEAN

#include "windows.h"
#include <cwchar>
#include <filesystem>
#include <tlhelp32.h>

static WCHAR g_AfterburnerLoc[MAX_PATH] = {0};
static HANDLE g_AfterburnerProcess = NULL;
static DWORD g_AfterburnerPID = 0;

void GetAfterburnerLocation() {
	if (g_AfterburnerLoc[0]) {
		return;
	}

	HKEY hKey;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
					  L"SOFTWARE\\WOW6432Node\\MSI Afterburner", 0, KEY_READ,
					  &hKey) == ERROR_SUCCESS) {
		DWORD size = sizeof(g_AfterburnerLoc);
		if (RegQueryValueExW(hKey, L"InstallPath", nullptr, nullptr,
							 (LPBYTE)g_AfterburnerLoc, &size) == ERROR_SUCCESS) {
			lstrcpynW(g_AfterburnerLoc,
					  (std::filesystem::path(g_AfterburnerLoc) / L"MSIAfterburner.exe").c_str(),
					  MAX_PATH);
		}
		RegCloseKey(hKey);
	}
}

bool IsAfterburnerRunning() {
	GetAfterburnerLocation();

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE)
		return false;

	PROCESSENTRY32W entry = {};
	entry.dwSize = sizeof(entry);

	bool found = false;
	if (Process32FirstW(snapshot, &entry)) {
		do {
			if (lstrcmpiW(entry.szExeFile, L"MSIAfterburner.exe") == 0) {
				g_AfterburnerPID = entry.th32ProcessID;
				g_AfterburnerProcess =
					OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, FALSE, entry.th32ProcessID);
				if (g_AfterburnerProcess) {
					LOG("Found Afterburner, PID=%lu\n", entry.th32ProcessID);
					if (g_AfterburnerLoc[0] == L'\0') {
						DWORD size = MAX_PATH;
						if (QueryFullProcessImageNameW(g_AfterburnerProcess, 0, g_AfterburnerLoc, &size))
							LOG("Resolved Afterburner path from process: %ls\n", g_AfterburnerLoc);
					}
				} else {
					LOG("Found Afterburner, PID=%lu, but failed to open process.\n",
						entry.th32ProcessID);
				}
				found = g_AfterburnerProcess != NULL;
				break;
			}
		} while (Process32NextW(snapshot, &entry));
	}

	CloseHandle(snapshot);
	return found;
}

bool WasAfterburnerRunning() { return WasAfterburnerEventSet(); }
void SetAfterburnerRunningState(bool state) {
	if (state) {
		SetAfterburnerEvent();
	}
}

static void KillProcessTree(DWORD pid) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		LOG("KillProcessTree: CreateToolhelp32Snapshot failed for PID %lu\n", pid);
		return;
	}

	PROCESSENTRY32W entry = {};
	entry.dwSize = sizeof(entry);

	if (Process32FirstW(snapshot, &entry)) {
		do {
			if (entry.th32ParentProcessID == pid) {
				LOG("KillProcessTree: Found child PID %lu (Parent: %lu, Exe: %ls), killing its tree...\n",
					entry.th32ProcessID, pid, entry.szExeFile);
				KillProcessTree(entry.th32ProcessID);
			}
		} while (Process32NextW(snapshot, &entry));
	}
	CloseHandle(snapshot);

	HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
	if (hProc) {
		LOG("KillProcessTree: Terminating PID %lu\n", pid);
		TerminateProcess(hProc, 0);
		CloseHandle(hProc);
	} else {
		LOG("KillProcessTree: Failed to open PID %lu for termination\n", pid);
	}
}

void KillAfterBurner() {
	if (!g_config.toggleDse)
		return;

	if (IsAfterburnerRunning()) {
		if (g_AfterburnerProcess) {
			CloseHandle(g_AfterburnerProcess);
			g_AfterburnerProcess = NULL;
		}

		if (g_AfterburnerPID) {
			KillProcessTree(g_AfterburnerPID);
			g_AfterburnerPID = 0;
		}

		LOG("Afterburner and its children killed\n");
	}
}

void StartAfterburner() {
	if (!g_config.toggleDse)
		return;

	if (!WasAfterburnerEventSet()) {
		LOG("Skipping Afterburner start because it was not running before.\n");
		return;
	}

	GetAfterburnerLocation();

	if (g_AfterburnerLoc[0]) {
		STARTUPINFOW si = {sizeof(si)};
		PROCESS_INFORMATION pi = {};

		const std::filesystem::path exe(g_AfterburnerLoc);

		std::wstring cmdLine = L"\"" + exe.wstring() + L"\"";

		if (!CreateProcessW(nullptr, cmdLine.data(), nullptr, nullptr, FALSE,
							0, nullptr, exe.parent_path().c_str(), &si, &pi)) {
			LOG("Failed to start Afterburner, error: %lu\n", GetLastError());
		} else {
			LOG("Afterburner started\n");
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
		}
	} else {
		LOG("Afterburner not found\n");
	}
}