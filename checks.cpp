#include "checks.h"
#include "config.h"
#include "log.h"
#define WIN32_LEAN_AND_MEAN

#include "windows.h"
#include <cwchar>
#include <shlwapi.h>
#include <tlhelp32.h>
#include "c_std/string/std_string.h"

#pragma comment(lib, "advapi32.lib")

#define SystemCodeIntegrityInformation 103

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
	ULONG Length;
	ULONG CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION, *PSYSTEM_CODEINTEGRITY_INFORMATION;

typedef NTSTATUS(WINAPI *PNtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength);

bool IsDseEnabledNtdll() {
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	if (!ntdll)
		ntdll = LoadLibraryW(L"ntdll.dll");
	if (!ntdll)
		return true;

	auto pNtQuerySystemInformation = (PNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
	if (!pNtQuerySystemInformation)
		return true;

	SYSTEM_CODEINTEGRITY_INFORMATION sci = {0};
	sci.Length = sizeof(sci);

	NTSTATUS status = pNtQuerySystemInformation(SystemCodeIntegrityInformation, &sci, sizeof(sci), nullptr);
	if (status >= 0) {
		if ((sci.CodeIntegrityOptions & 1) == 0)
			return false;
		if (sci.CodeIntegrityOptions & 2)
			return false;
		return true;
	}
	return true;
}

static bool CheckRegDword(HKEY hKeyRoot, LPCWSTR subKey, LPCWSTR valueName, DWORD expectedValue) {
	HKEY hKey;
	if (RegOpenKeyExW(hKeyRoot, subKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
		DWORD data;
		DWORD dataSize = sizeof(data);
		if (RegQueryValueExW(hKey, valueName, nullptr, nullptr, (LPBYTE)&data, &dataSize) == ERROR_SUCCESS) {
			RegCloseKey(hKey);
			return data == expectedValue;
		}
		RegCloseKey(hKey);
	}
	return false;
}

bool IsVbsLocked() {
	return CheckRegDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", L"Locked", 1);
}

bool IsHvciLocked() {
	return CheckRegDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity", L"Locked", 1);
}

bool IsVbsEnabled() {
	bool regVbs = CheckRegDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", L"EnableVirtualizationBasedSecurity", 1);
	return regVbs || IsVbsLocked();
}

bool IsHvciEnabled() {
	bool regHvci = CheckRegDword(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity", L"Enabled", 1);
	return regHvci || IsHvciLocked();
}

void SystemChecks() {
	bool hvciEnabled = IsHvciEnabled();
	bool vbsEnabled = IsVbsEnabled();

	LOG("[DSE-DLL] hvciEnabled: %d, vbsEnabled: %d\n", hvciEnabled, vbsEnabled);

	if (hvciEnabled || vbsEnabled) {
		MessageBoxW(0, L"You have vbs and hvci enabled, please disable it!\n", L"Error", MB_OK | MB_ICONERROR | MB_TOPMOST | MB_SETFOREGROUND);
		ExitProcess(0);
	}
}

void ManageProblematicServices() {
	SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
	if (!hSCM) {
		LOG("[DSE-DLL] OpenSCManager failed: %lu\n", GetLastError());
		return;
	}

	if (g_config.problematicServices) {
		size_t svcCount = vector_size(g_config.problematicServices);
		for (size_t i = 0; i < svcCount; ++i) {
			ProblematicService** psvc = (ProblematicService**)vector_at(g_config.problematicServices, i);
			ProblematicService* svc = psvc ? *psvc : nullptr;
			if (!svc) continue;
			wchar_t* namew = string_to_unicode(string_c_str(svc->name));
			SC_HANDLE hService = namew ? OpenServiceW(hSCM, namew, SERVICE_ALL_ACCESS) : NULL;
		if (hService) {
			if (svc->action == ServiceActionType::STOP) {
				SERVICE_STATUS status;
				ControlService(hService, SERVICE_CONTROL_STOP, &status);
				LOG("[DSE-DLL] Stopped service %ls\n", namew);
			} else if (svc->action == ServiceActionType::DELETE_SVC) {
				DeleteService(hService);
				LOG("[DSE-DLL] Deleted service %ls\n", namew);
			}
			CloseServiceHandle(hService);
		} else {
			LOG("[DSE-DLL] Could not open service %ls (err %lu)\n", namew, GetLastError());
		}
		if (namew) free(namew);
		}
	}
	CloseServiceHandle(hSCM);
}

void RestoreProblematicServices() {
	SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
	if (!hSCM)
		return;

	if (g_config.problematicServices) {
		size_t svcCount = vector_size(g_config.problematicServices);
		for (size_t i = 0; i < svcCount; ++i) {
			ProblematicService** psvc = (ProblematicService**)vector_at(g_config.problematicServices, i);
			ProblematicService* svc = psvc ? *psvc : nullptr;
			if (!svc) continue;
			if (svc->action == ServiceActionType::STOP) {
				wchar_t* namew = string_to_unicode(string_c_str(svc->name));
				SC_HANDLE hService = namew ? OpenServiceW(hSCM, namew, SERVICE_ALL_ACCESS) : NULL;
				if (hService) {
					if (!StartServiceW(hService, 0, nullptr)) {
						DWORD err = GetLastError();
						if (err != ERROR_SERVICE_ALREADY_RUNNING) {
							LOG("[DSE-DLL] Failed to start service %ls (err %lu)\n", namew, err);
						} else {
							LOG("[DSE-DLL] Service %ls was already running (skipping)\n", namew);
						}
					} else {
						LOG("[DSE-DLL] Restored (started) service %ls\n", namew);
					}
					CloseServiceHandle(hService);
				}
				if (namew) free(namew);
			}
		}
	}
	CloseServiceHandle(hSCM);
}

static void KillProcessTreeByName(const wchar_t *name) {
	if (!name) return;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE)
		return;

	PROCESSENTRY32W entry = {};
	entry.dwSize = sizeof(entry);

	if (Process32FirstW(snapshot, &entry)) {
		do {
			if (lstrcmpiW(entry.szExeFile, name) == 0) {
				HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, entry.th32ProcessID);
				if (hProc) {
					TerminateProcess(hProc, 0);
					CloseHandle(hProc);
					LOG("[DSE-DLL] Killed task %ls (PID: %lu)\n", name, entry.th32ProcessID);
				}
			}
		} while (Process32NextW(snapshot, &entry));
	}
	CloseHandle(snapshot);
}

void ManageProblematicTasks() {
	if (g_config.problematicTasks) {
		size_t tcount = vector_size(g_config.problematicTasks);
		for (size_t i = 0; i < tcount; ++i) {
			String** pst = (String**)vector_at(g_config.problematicTasks, i);
			String* stok = pst ? *pst : nullptr;
			if (!stok) continue;
			wchar_t* taskw = string_to_unicode(string_c_str(stok));
			if (!taskw) continue;
			KillProcessTreeByName(taskw);
			free(taskw);
		}
	}
}

void WaitForWatchdogToExit() {
	// 1. Check for new watchdog mutex
	HANDLE hMutex = OpenMutexW(SYNCHRONIZE, FALSE, L"Local\\DseDll_WatchdogAlive");
	if (hMutex) {
		LOG("[DSE-DLL] Watchdog mutex found, waiting...\n");
		WaitForSingleObject(hMutex, INFINITE);
		CloseHandle(hMutex);
		LOG("[DSE-DLL] Watchdog finished.\n");
		return;
	}

	extern HMODULE g_hModule;
	WCHAR ourDllName[MAX_PATH];
	if (!GetModuleFileNameW(g_hModule, ourDllName, MAX_PATH))
		return;

	bool found;
	do {
		found = false;
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snapshot != INVALID_HANDLE_VALUE) {
			PROCESSENTRY32W entry = {};
			entry.dwSize = sizeof(entry);
			if (Process32FirstW(snapshot, &entry)) {
				do {
					if (lstrcmpiW(entry.szExeFile, L"rundll32.exe") == 0) {
						HANDLE hModSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, entry.th32ProcessID);
						if (hModSnap != INVALID_HANDLE_VALUE) {
							MODULEENTRY32W modEntry = {};
							modEntry.dwSize = sizeof(modEntry);
							if (Module32FirstW(hModSnap, &modEntry)) {
								do {
									if (lstrcmpiW(modEntry.szExePath, ourDllName) == 0) {
										found = true;
										LOG("[DSE-DLL] Found watchdog process (PID %lu) via module, waiting...\n", entry.th32ProcessID);
										HANDLE hWait = OpenProcess(SYNCHRONIZE, FALSE, entry.th32ProcessID);
										if (hWait) {
											WaitForSingleObject(hWait, INFINITE);
											CloseHandle(hWait);
										} else {
											Sleep(500);
										}
										break;
									}
								} while (Module32NextW(hModSnap, &modEntry));
							}
							CloseHandle(hModSnap);
						}
					}
					if (found)
						break;
				} while (Process32NextW(snapshot, &entry));
			}
			CloseHandle(snapshot);
		}
	} while (found);
}