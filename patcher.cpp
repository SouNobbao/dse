#include "patcher.h"

#include "config.h"
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
		LOG("[DSE-DLL] DrvLoader initialization failed (PDB unavailable?)\n");
		return false;
	}
	g_loaderInitialized = true;
	return true;
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
	LOG("[DSE-DLL] DSE status: %s\n", disabled ? "DISABLED" : "ENABLED");

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
		LOG("[DSE-DLL] Skipping DSE disable because process is not elevated\n");
		return;
	}

	// Try Safe method first (PDB + SeCiCallbacks)
	if (EnsureLoaderInitialized() && g_loader.BypassDSE()) {
		return;
	}
	LOG("[DSE-DLL] Safe method failed, offering standard fallback\n");

	int choice = g_config.ignoreWarnings ? IDOK : MessageBoxW(nullptr,
		L"PDB-based DSE bypass failed.\n\n"
		L"Switch to standard method (g_CiOptions)?\n"
		L"This modifies kernel code integrity flags directly.",
		L"Warning", MB_OKCANCEL | MB_ICONWARNING | MB_SYSTEMMODAL);

	if (choice != IDOK) {
		LOG("[DSE-DLL] User cancelled standard fallback\n");
		return;
	}

	EnsureResourceSet();
	if (!g_loader.DisableDSEStandard()) {
		LOG("[DSE-DLL] Standard method also failed\n");
	}
}

void EnableDse() {
	KillAfterBurner();
	if (!IsRunningAsAdmin()) {
		LOG("[DSE-DLL] Skipping DSE enable because process is not elevated\n");
		if (WasAfterburnerRunning()) StartAfterburner();
		return;
	}

	// Check which method was used via registry
	auto savedCallback = ConfigManager::LoadOriginalCallbackFromRegistry();
	if (savedCallback) {
		// Safe method was used — try drvloader restore
		if (EnsureLoaderInitialized() && g_loader.RestoreDSE()) {
			if (WasAfterburnerRunning()) StartAfterburner();
			return;
		}
		LOG("[DSE-DLL] Safe restore failed, trying standard restore\n");
	}

	// Standard method restore (or safe restore failed)
	EnsureResourceSet();
	if (!g_loader.RestoreDSEStandard()) {
		LOG("[DSE-DLL] Standard restore failed\n");
	}

	if (WasAfterburnerRunning()) StartAfterburner();
}

void DeletePatcherFile() {
	// No-op: driver cleanup handled internally by DrvLoader
}
