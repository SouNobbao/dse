#include "patcher.h"

#include "config.h"
#include "common.h"
#include "afterburner.h"
#include "log.h"

#include "drvloader/DrvCore.h"
#include "drvloader/ConfigManager.h"
#include "drvloader/rtcore_resource.h"

#include <stdio.h>
#include <processthreadsapi.h>
#include <shlwapi.h>
#include <winnt.h>

#pragma comment(lib, "shlwapi.lib")

static DrvLoader g_loader;
static bool g_loaderInitialized = false;
static bool g_resourceSet = false;

static void EnsureResourceSet() {
	if (g_resourceSet) return;
	g_loader.embeddedResourceData = rtcore_resource_data;
	g_loader.embeddedResourceSize = rtcore_resource_data_len;
	g_resourceSet = true;
}

static bool EnsureLoaderInitialized() {
	if (g_loaderInitialized) return true;
	EnsureResourceSet();
	if (!g_loader.Initialize()) {
		LOG("DrvLoader initialization failed (PDB unavailable?)\n");
		return false;
	}
	g_loaderInitialized = true;
	return true;
}

// Restore dse under rundll32.exe
static bool RestoreDseExternal() {
	if (IsHostPassthrough())
		return false;

	WCHAR dllPath[MAX_PATH]{};
	if (!GetModuleFileNameW(g_hModule, dllPath, MAX_PATH))
		return false;

	WCHAR cmdLine[MAX_PATH * 4]{};
	wsprintfW(cmdLine, L"rundll32.exe \"%s\",DseRestoreEntryW", dllPath);

	LOG("Spawning external DSE restore: %ls\n", cmdLine);

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
					CreateProcessW(nullptr, cmdLine, nullptr, nullptr, FALSE,
								   CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
								   nullptr, nullptr, &si.StartupInfo, &pi);

	bool restored = false;
	if (ok) {
		WaitForSingleObject(pi.hProcess, INFINITE);
		DWORD exitCode = 0;
		GetExitCodeProcess(pi.hProcess, &exitCode);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		LOG("rundll32 restore exited with code %lu\n", exitCode);

		restored = !ConfigManager::LoadOriginalCallbackFromRegistry().has_value();
		if (restored)
			LOG("External restore succeeded\n");
		else
			LOG("External restore did not clear patch state\n");
	} else {
		LOG("Failed to spawn external restore, err: %lu\n", GetLastError());
	}

	if (attrsReady)
		DeleteProcThreadAttributeList(attrs);
	if (attrs)
		HeapFree(GetProcessHeap(), 0, attrs);

	return restored;
}

extern "C" __declspec(dllexport) void CALLBACK DseRestoreEntryW(HWND hwnd, HINSTANCE hinst, LPWSTR lpszCmdLine, int nCmdShow) {
	(void)hwnd; (void)hinst; (void)lpszCmdLine; (void)nCmdShow;

	InitLogPath(g_hModule);
	LoadDseConfig(g_hModule);
	g_loggingEnabled = g_config.logging;

	DrvLoader loader;
	loader.embeddedResourceData = rtcore_resource_data;
	loader.embeddedResourceSize = rtcore_resource_data_len;

	bool restored = loader.Initialize() && loader.RestoreDSE();
	LOG("rundll32 DSE restore %s\n", restored ? "succeeded" : "failed");

	ExitProcess(restored ? 0 : 1);
}

bool IsRunningAsAdmin() {
	BOOL isAdmin = FALSE;
	PSID adminGroup = nullptr;
	SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
	if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
								 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
								 &adminGroup)) {
		CheckTokenMembership(nullptr, adminGroup, &isAdmin);
		FreeSid(adminGroup);
	}
	return isAdmin != FALSE;
}

bool IsDseEnabled(bool defaultVal) {
	bool afterburnerKilledByUs = false;
	if (IsAfterburnerRunning()) {
		KillAfterBurner();
		afterburnerKilledByUs = true;
	}

	if (!IsRunningAsAdmin()) {
		if (afterburnerKilledByUs) {
			bool oldState = WasAfterburnerRunning();
			SetAfterburnerRunningState(true);
			StartAfterburner();
			SetAfterburnerRunningState(oldState);
		}
		return defaultVal;
	}

	bool disabled = ConfigManager::IsPatchedFromRegistry();
	LOG("DSE status: %s\n", disabled ? "DISABLED" : "ENABLED");

	if (afterburnerKilledByUs) {
		bool oldState = WasAfterburnerRunning();
		SetAfterburnerRunningState(true);
		StartAfterburner();
		SetAfterburnerRunningState(oldState);
	}

	return !disabled;
}

void DisableDse() {
	KillAfterBurner();
	if (!IsRunningAsAdmin()) {
		LOG("Skipping DSE disable because process is not elevated\n");
		return;
	}

	if (EnsureLoaderInitialized() && g_loader.BypassDSE()) {
		return;
	}
	LOG("Safe method failed, offering standard fallback\n");

	int choice = g_config.ignoreWarnings ? IDOK : MessageBoxW(nullptr,
		L"PDB-based DSE bypass failed.\n\n"
		L"Switch to standard method (g_CiOptions)?\n"
		L"This modifies kernel code integrity flags directly.",
		L"Warning", MB_OKCANCEL | MB_ICONWARNING | MB_SYSTEMMODAL);

	if (choice != IDOK) {
		LOG("User cancelled standard fallback\n");
		return;
	}

	EnsureResourceSet();
	if (!g_loader.DisableDSEStandard()) {
		LOG("Standard method also failed\n");
	}
}

void EnableDse() {
	KillAfterBurner();
	if (!IsRunningAsAdmin()) {
		LOG("Skipping DSE enable because process is not elevated\n");
		if (WasAfterburnerRunning()) StartAfterburner();
		return;
	}

	auto method = ConfigManager::GetPatchMethodFromRegistry();
	auto savedCallback = ConfigManager::LoadOriginalCallbackFromRegistry();
	const bool pdbMethod = (method == L"PDB") || (method.empty() && savedCallback.has_value());

	if (pdbMethod) {
		if (!savedCallback) {
			LOG("PDB patch state has no saved callback - nothing to restore\n");
			if (WasAfterburnerRunning()) StartAfterburner();
			return;
		}

		if (EnsureLoaderInitialized() && g_loader.RestoreDSE()) {
			if (WasAfterburnerRunning()) StartAfterburner();
			return;
		}
		LOG("Safe restore failed in-process, retrying from rundll32 process\n");

		if (RestoreDseExternal()) {
			if (WasAfterburnerRunning()) StartAfterburner();
			return;
		}
		LOG("External restore also failed, keeping saved callback state.\n");
		if (WasAfterburnerRunning()) StartAfterburner();
		return;
	}

	// Standard method restore (g_CiOptions)
	EnsureResourceSet();
	if (!g_loader.RestoreDSEStandard()) {
		LOG("Standard restore failed\n");
	}

	if (WasAfterburnerRunning()) StartAfterburner();
}