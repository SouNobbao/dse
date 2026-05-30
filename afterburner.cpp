#include "log.h"
#define WIN32_LEAN_AND_MEAN

#include "windows.h"
#include <cwchar>
#include <shlwapi.h>
#include <tlhelp32.h>

#pragma comment(lib, "shlwapi.lib")

static WCHAR g_AfterburnerLoc[MAX_PATH] = {0};
static HANDLE g_AfterburnerProcess = NULL;
static DWORD g_AfterburnerPID = 0;
static bool g_IsAfterburnerRunning = false;

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
			lstrcatW(g_AfterburnerLoc, L"\\MSIAfterburner.exe");
		}
		RegCloseKey(hKey);
	}
}

bool IsAfterburnerRunning() {
	GetAfterburnerLocation();

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		return -1;
	}

	PROCESSENTRY32W entry = {};
	entry.dwSize = sizeof(entry);

	if (Process32FirstW(snapshot, &entry)) {
		do {
			if (lstrcmpiW(entry.szExeFile, L"MSIAfterburner.exe") == 0) {
				g_AfterburnerPID = entry.th32ProcessID;
				g_AfterburnerProcess =
					OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, FALSE, entry.th32ProcessID);
				if (g_AfterburnerProcess) {
					LOG("[DSE-DLL] Found Afterburner, PID=%lu\n", entry.th32ProcessID);
					if (g_AfterburnerLoc[0] == L'\0') {
						DWORD size = MAX_PATH;
						if (QueryFullProcessImageNameW(g_AfterburnerProcess, 0, g_AfterburnerLoc, &size)) {
							LOG("[DSE-DLL] Resolved Afterburner path from process: %ls\n", g_AfterburnerLoc);
						}
					}
				} else {
					LOG("[DSE-DLL] Found Afterburner, PID=%lu, but failed to open process.\n",
						entry.th32ProcessID);
				}
				return g_AfterburnerProcess != NULL;
			}
		} while (Process32NextW(snapshot, &entry));
	}

	CloseHandle(snapshot);
	return FALSE;
}

bool WasAfterburnerRunning() { return g_IsAfterburnerRunning; }
void SetAfterburnerRunningState(bool state) { g_IsAfterburnerRunning = state; }

static void KillProcessTree(DWORD pid) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		LOG("[DSE-DLL] KillProcessTree: CreateToolhelp32Snapshot failed for PID %lu\n", pid);
		return;
	}

	PROCESSENTRY32W entry = {};
	entry.dwSize = sizeof(entry);

	if (Process32FirstW(snapshot, &entry)) {
		do {
			if (entry.th32ParentProcessID == pid) {
				LOG("[DSE-DLL] KillProcessTree: Found child PID %lu (Parent: %lu, Exe: %ls), killing its tree...\n",
					entry.th32ProcessID, pid, entry.szExeFile);
				KillProcessTree(entry.th32ProcessID);
			}
		} while (Process32NextW(snapshot, &entry));
	}
	CloseHandle(snapshot);

	HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
	if (hProc) {
		LOG("[DSE-DLL] KillProcessTree: Terminating PID %lu\n", pid);
		TerminateProcess(hProc, 0);
		CloseHandle(hProc);
	} else {
		LOG("[DSE-DLL] KillProcessTree: Failed to open PID %lu for termination\n", pid);
	}
}

void KillAfterBurner() {
	if (IsAfterburnerRunning()) {
		if (g_AfterburnerProcess) {
			CloseHandle(g_AfterburnerProcess);
			g_AfterburnerProcess = NULL;
		}

		if (g_AfterburnerPID) {
			KillProcessTree(g_AfterburnerPID);
			g_AfterburnerPID = 0;
		}

		LOG("[DSE-DLL] Afterburner and its children killed\n");
	}
}

void StartAfterburner() {
	if (!g_IsAfterburnerRunning) {
		LOG("[DSE-DLL] Skipping Afterburner start because it was not running before.\n");
		return;
	}

	GetAfterburnerLocation();

	if (g_AfterburnerLoc[0]) {
		STARTUPINFOW si = {sizeof(si)};
		PROCESS_INFORMATION pi = {};

		WCHAR workDir[MAX_PATH];
		lstrcpyW(workDir, g_AfterburnerLoc);
		PathRemoveFileSpecW(workDir);

		WCHAR cmdLine[MAX_PATH + 2];
		wsprintfW(cmdLine, L"\"%s\"", g_AfterburnerLoc);

		if (!CreateProcessW(nullptr, cmdLine, nullptr, nullptr, FALSE,
							0, nullptr, workDir, &si, &pi)) {
			LOG("[DSE-DLL] Failed to start Afterburner, error: %lu\n", GetLastError());
		} else {
			LOG("[DSE-DLL] Afterburner started\n");
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
			g_IsAfterburnerRunning = FALSE;
		}
	} else {
		LOG("[DSE-DLL] Afterburner not found\n");
	}
}