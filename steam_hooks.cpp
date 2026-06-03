#define WIN32_LEAN_AND_MEAN

#include "config.h"
#include "log.h"
#include "minhook/include/MinHook.h"
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <psapi.h>
#include <shlwapi.h>
#include <vector>
#include <windows.h>

static bool IATHook(HMODULE hModule, const char *dllName, const char *funcName,
					void *hookFunc, void **origFunc) {
	if (!hModule || !dllName || !funcName || !hookFunc)
		return false;

	PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)hModule;
	if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return false;
	PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)((BYTE *)hModule + dosHdr->e_lfanew);
	if (ntHdr->Signature != IMAGE_NT_SIGNATURE)
		return false;

	DWORD impRVA = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (!impRVA)
		return false;

	PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE *)hModule + impRVA);

	for (; importDesc->Name; importDesc++) {
		const char *modName = (const char *)((BYTE *)hModule + importDesc->Name);
		if (_stricmp(modName, dllName) != 0)
			continue;

		PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)((BYTE *)hModule + importDesc->OriginalFirstThunk);
		PIMAGE_THUNK_DATA iatThunk = (PIMAGE_THUNK_DATA)((BYTE *)hModule + importDesc->FirstThunk);

		for (; origThunk->u1.AddressOfData; origThunk++, iatThunk++) {
			if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal))
				continue;
			PIMAGE_IMPORT_BY_NAME importByName =
				(PIMAGE_IMPORT_BY_NAME)((BYTE *)hModule + origThunk->u1.AddressOfData);
			if (strcmp(importByName->Name, funcName) != 0)
				continue;

			if (origFunc)
				*origFunc = (void *)iatThunk->u1.Function;

			DWORD oldProtect;
			VirtualProtect(&iatThunk->u1.Function, sizeof(void *), PAGE_READWRITE, &oldProtect);
			iatThunk->u1.Function = (ULONG_PTR)hookFunc;
			VirtualProtect(&iatThunk->u1.Function, sizeof(void *), oldProtect, &oldProtect);
			return true;
		}
	}
	return false;
}

static int IATHookByAddress(void *realFunc, void *hookFunc, void **origFunc) {
	if (!realFunc || !hookFunc)
		return 0;

	if (origFunc)
		*origFunc = realFunc;

	int count = 0;
	HMODULE hMods[256];
	DWORD cbNeeded;
	HANDLE hProc = GetCurrentProcess();

	if (!EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded))
		return 0;

	int nMods = cbNeeded / sizeof(HMODULE);
	for (int m = 0; m < nMods; m++) {
		HMODULE hMod = hMods[m];
		PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)hMod;
		if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE)
			continue;
		PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)((BYTE *)hMod + dosHdr->e_lfanew);
		if (ntHdr->Signature != IMAGE_NT_SIGNATURE)
			continue;

		DWORD impRVA = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		DWORD impSize = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
		if (!impRVA || !impSize)
			continue;

		PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE *)hMod + impRVA);
		for (; importDesc->Name; importDesc++) {
			if (!importDesc->FirstThunk)
				continue;
			PIMAGE_THUNK_DATA iatThunk = (PIMAGE_THUNK_DATA)((BYTE *)hMod + importDesc->FirstThunk);
			for (; iatThunk->u1.Function; iatThunk++) {
				if ((void *)iatThunk->u1.Function == realFunc) {
					DWORD oldProtect;
					VirtualProtect(&iatThunk->u1.Function, sizeof(void *), PAGE_READWRITE, &oldProtect);
					iatThunk->u1.Function = (ULONG_PTR)hookFunc;
					VirtualProtect(&iatThunk->u1.Function, sizeof(void *), oldProtect, &oldProtect);
					count++;
				}
			}
		}
	}
	return count;
}

struct IATHookEntry {
	const char *funcName;
	void *hookFunc;
	void *origFunc;
};
static IATHookEntry g_iatHookTable[64];
static int g_iatHookCount = 0;

static void RegisterIATHook(const char *funcName, void *hookFunc, void *origFunc) {
	if (g_iatHookCount >= 64)
		return;
	g_iatHookTable[g_iatHookCount].funcName = funcName;
	g_iatHookTable[g_iatHookCount].hookFunc = hookFunc;
	g_iatHookTable[g_iatHookCount].origFunc = origFunc;
	g_iatHookCount++;
}

static void *FindIATHookByName(const char *funcName) {
	for (int i = 0; i < g_iatHookCount; i++) {
		if (strcmp(g_iatHookTable[i].funcName, funcName) == 0)
			return g_iatHookTable[i].hookFunc;
	}
	return nullptr;
}

typedef FARPROC(WINAPI *pfn_GetProcAddress)(HMODULE, LPCSTR);
static pfn_GetProcAddress Orig_GetProcAddress = nullptr;
static HMODULE g_hSteamApiModule = nullptr;

static FARPROC WINAPI Hooked_GetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
	FARPROC result = Orig_GetProcAddress(hModule, lpProcName);
	if (result && hModule == g_hSteamApiModule && !IS_INTRESOURCE(lpProcName)) {
		void *hook = FindIATHookByName(lpProcName);
		if (hook) {
			LOG("[DSE-DLL] GetProcAddress(\"%s\") intercepted -> hook\n", lpProcName);
			return (FARPROC)hook;
		}
	}
	return result;
}

static uint64_t g_fakeSteamID = 70000000000000000ULL; // default SteamID
static bool g_hasConfiguredSteamID = false;
static bool g_forceOffline = false;
static bool g_steamHooked = false;
static uint32_t g_mainAppId = 0;
static char g_steamPath[MAX_PATH] = {}; // Steam install path (UTF-8)

static bool g_unlockAllDlcs = true;
struct DLCInfo {
	uint32_t appId;
	char name[128];
};
static std::vector<DLCInfo> g_unlockedDlcs;

extern HMODULE g_hModule;

// Steam API hooks

// Read config from steam_settings.
static void LoadSteamConfigFromDll(HMODULE hSteamApi) {
	WCHAR dllDir[MAX_PATH]{};
	if (!GetModuleFileNameW(hSteamApi, dllDir, MAX_PATH))
		return;
	PathRemoveFileSpecW(dllDir);

	WCHAR userIniPath[MAX_PATH]{};
	lstrcpynW(userIniPath, dllDir, MAX_PATH);
	PathAppendW(userIniPath, L"steam_settings\\configs.user.ini");

	if (GetFileAttributesW(userIniPath) == INVALID_FILE_ATTRIBUTES) {
		GetModuleFileNameW(g_hModule, dllDir, MAX_PATH);
		PathRemoveFileSpecW(dllDir);
		lstrcpynW(userIniPath, dllDir, MAX_PATH);
		PathAppendW(userIniPath, L"steam_settings\\configs.user.ini");
	}

	if (GetFileAttributesW(userIniPath) == INVALID_FILE_ATTRIBUTES) {
		LOG("[DSE-DLL] No steam_settings/configs.user.ini found, using default "
			"SteamID\n");
	} else {
		WCHAR buf[64]{};
		GetPrivateProfileStringW(L"user::general", L"account_steamid", L"0", buf,
								 ARRAYSIZE(buf), userIniPath);
		uint64_t parsed = 0;
		for (int i = 0; buf[i] >= L'0' && buf[i] <= L'9'; i++)
			parsed = parsed * 10 + (buf[i] - L'0');
		if (parsed > 0) {
			g_fakeSteamID = parsed;
			g_hasConfiguredSteamID = true;
			LOG("[DSE-DLL] Config: SteamID = %llu (from configs.user.ini)\n",
				(unsigned long long)g_fakeSteamID);
		} else {
			LOG("[DSE-DLL] No valid account_steamid in configs.user.ini, using "
				"default\n");
		}
	}

	WCHAR mainIniPath[MAX_PATH]{};
	lstrcpynW(mainIniPath, dllDir, MAX_PATH);
	PathAppendW(mainIniPath, L"steam_settings\\configs.main.ini");

	WCHAR rootOfflineTxt[MAX_PATH]{};
	lstrcpynW(rootOfflineTxt, dllDir, MAX_PATH);
	PathAppendW(rootOfflineTxt, L"offline.txt");

	WCHAR settingsOfflineTxt[MAX_PATH]{};
	lstrcpynW(settingsOfflineTxt, dllDir, MAX_PATH);
	PathAppendW(settingsOfflineTxt, L"steam_settings\\offline.txt");

	bool hasOfflineTxt = (GetFileAttributesW(rootOfflineTxt) != INVALID_FILE_ATTRIBUTES) ||
						 (GetFileAttributesW(settingsOfflineTxt) != INVALID_FILE_ATTRIBUTES);

	WCHAR offBuf[16]{};
	GetPrivateProfileStringW(L"main::connectivity", L"offline", L"0", offBuf,
							 ARRAYSIZE(offBuf), mainIniPath);
	g_forceOffline = hasOfflineTxt || (offBuf[0] == L'1');
	LOG("[DSE-DLL] Config: offline = %s\n", g_forceOffline ? "true" : "false");

	WCHAR dseIniPath[MAX_PATH]{};
	lstrcpynW(dseIniPath, dllDir, MAX_PATH);
	PathAppendW(dseIniPath, L"steam_settings\\configs.dse.ini");

	WCHAR pathBuf[MAX_PATH]{};
	GetPrivateProfileStringW(L"main", L"steam_path", L"", pathBuf,
							 ARRAYSIZE(pathBuf), dseIniPath);
	if (pathBuf[0]) {
		WideCharToMultiByte(CP_UTF8, 0, pathBuf, -1, g_steamPath, MAX_PATH, nullptr,
							nullptr);
		LOG("[DSE-DLL] Config: steam_path = %s\n", g_steamPath);
	}

	auto TryReadAppId = [](LPCWSTR path, uint32_t &outId) -> bool {
		HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
								   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (hFile == INVALID_HANDLE_VALUE)
			return false;
		char idBuf[32]{};
		DWORD read = 0;
		ReadFile(hFile, idBuf, sizeof(idBuf) - 1, &read, nullptr);
		CloseHandle(hFile);
		uint32_t appId = 0;
		for (DWORD i = 0; i < read && idBuf[i] >= '0' && idBuf[i] <= '9'; i++)
			appId = appId * 10 + (idBuf[i] - '0');
		if (appId > 0) {
			outId = appId;
			return true;
		}
		return false;
	};

	WCHAR exeDir[MAX_PATH]{};
	GetModuleFileNameW(nullptr, exeDir, MAX_PATH);
	PathRemoveFileSpecW(exeDir);

	WCHAR rootAppIdPath[MAX_PATH]{};
	lstrcpynW(rootAppIdPath, exeDir, MAX_PATH);
	PathAppendW(rootAppIdPath, L"steam_appid.txt");

	WCHAR settingsAppIdPath[MAX_PATH]{};
	lstrcpynW(settingsAppIdPath, dllDir, MAX_PATH);
	PathAppendW(settingsAppIdPath, L"steam_settings\\steam_appid.txt");

	WCHAR appIniPath[MAX_PATH]{};
	lstrcpynW(appIniPath, dllDir, MAX_PATH);
	PathAppendW(appIniPath, L"steam_settings\\configs.app.ini");

	WCHAR dlcsBuf[4096]{};
	if (GetPrivateProfileSectionW(L"app::dlcs", dlcsBuf, ARRAYSIZE(dlcsBuf), appIniPath) > 0) {
		WCHAR *p = dlcsBuf;
		while (*p) {
			WCHAR *eq = wcschr(p, L'=');
			if (eq) {
				*eq = 0; // null terminate key
				WCHAR *val = eq + 1;
				if (wcscmp(p, L"unlock_all") == 0) {
					g_unlockAllDlcs = (val[0] == L'1');
				} else {
					uint32_t dlcId = 0;
					for (int i = 0; p[i] >= L'0' && p[i] <= L'9'; i++)
						dlcId = dlcId * 10 + (p[i] - L'0');
					if (dlcId > 0) {
						DLCInfo info = {dlcId, {0}};
						WideCharToMultiByte(CP_UTF8, 0, val, -1, info.name, sizeof(info.name) - 1, nullptr, nullptr);
						g_unlockedDlcs.push_back(info);
					}
				}
			}
			p += wcslen(p) + 1; // next string
		}
		LOG("[DSE-DLL] Config: unlock_all=%d, %d specific DLCs loaded from configs.app.ini\n", (int)g_unlockAllDlcs, (int)g_unlockedDlcs.size());
	}

	uint32_t appId = 0;
	bool foundInRoot = TryReadAppId(rootAppIdPath, appId);
	bool foundInSettings = !foundInRoot && TryReadAppId(settingsAppIdPath, appId);
	if (appId > 0)
		g_mainAppId = appId;

	if (foundInRoot) {
		LOG("[DSE-DLL] steam_appid.txt found in game root, AppId = %u\n", appId);
	} else if (foundInSettings) {
		LOG("[DSE-DLL] steam_appid.txt found in steam_settings, AppId = %u\n",
			appId);
		if (!CopyFileW(settingsAppIdPath, rootAppIdPath, FALSE)) {
			LOG("[DSE-DLL] WARNING: Failed to copy steam_appid.txt to root (err "
				"%lu)\n",
				GetLastError());
		} else {
			LOG("[DSE-DLL] Copied steam_appid.txt to game root\n");
		}
	} else {
		LOG("[DSE-DLL] WARNING: steam_appid.txt not found in root or "
			"steam_settings\n");
	}

	if (appId > 0) {
		char envBuf[32];
		sprintf(envBuf, "%u", appId);
		SetEnvironmentVariableA("SteamAppId", envBuf);
		SetEnvironmentVariableA("SteamGameId", envBuf);
		LOG("[DSE-DLL] Set env SteamAppId/SteamGameId = %u\n", appId);
	}
}

// Typedefs
typedef bool (*pfn_RestartAppIfNecessary)(uint32_t);
typedef uint64_t (*pfn_GetSteamID)(void *);
typedef bool (*pfn_BLoggedOn)(void *);
typedef int (*pfn_GetPersonaState)(void *);
typedef bool (*pfn_SteamAPI_Init)();
typedef int (*pfn_SteamAPI_InitFlat)(char *);
typedef int (*pfn_SteamInternal_Init)(const char *, char *);
typedef bool (*pfn_IsSteamRunning)();
typedef const char *(*pfn_GetSteamInstallPath)();
typedef void *(*pfn_SteamInternal_FindOrCreateUserInterface)(int32_t,
															 const char *);

typedef int32_t (*pfn_SteamAPI_GetHSteamUser)();

static pfn_RestartAppIfNecessary Orig_RestartApp = nullptr;
static pfn_GetSteamID Orig_GetSteamID = nullptr;
static pfn_BLoggedOn Orig_BLoggedOn = nullptr;
static pfn_GetPersonaState Orig_GetPersonaState = nullptr;
static pfn_SteamAPI_Init Orig_SteamAPI_Init = nullptr;
static pfn_SteamAPI_InitFlat Orig_SteamAPI_InitFlat = nullptr;
static pfn_SteamInternal_Init Orig_SteamInternal_Init = nullptr;
static pfn_IsSteamRunning Orig_IsSteamRunning = nullptr;
static pfn_GetSteamInstallPath Orig_GetSteamInstallPath = nullptr;
static pfn_SteamInternal_FindOrCreateUserInterface
	Orig_FindOrCreateUserInterface = nullptr;
static pfn_SteamAPI_GetHSteamUser Orig_GetHSteamUser = nullptr;

typedef void *(*pfn_SteamInternal_CreateInterface)(const char *pszVersion);
static pfn_SteamInternal_CreateInterface Orig_SteamInternal_CreateInterface = nullptr;

// VTable state
static void **g_pISteamUserVTable = nullptr;
static void **g_pISteamFriendsVTable = nullptr;

// VTable typedefs
// CSteamID is returned through a hidden return buffer for MSVC x64.
// VTable calls pass the instance first; return buffer follows.
typedef void *(*pfn_GetSteamID_vtable)(void *self, uint64_t *pOut);
static pfn_GetSteamID_vtable Orig_GetSteamID_vtable = nullptr;

typedef bool (*pfn_BLoggedOn_vtable)(void *);
static pfn_BLoggedOn_vtable Orig_BLoggedOn_vtable = nullptr;

typedef int (*pfn_GetPersonaState_vtable)(void *);
static pfn_GetPersonaState_vtable Orig_GetPersonaState_vtable = nullptr;

typedef uint32_t (*pfn_GetAppOwnershipTicketData_vtable)(void *self, uint32_t nAppId, void *pvBuffer, uint32_t cbBufferLength, uint32_t *piAppId, uint32_t *piSteamId, uint32_t *piSignature, uint32_t *pcbSignature);
static pfn_GetAppOwnershipTicketData_vtable Orig_GetAppOwnershipTicketData_vtable = nullptr;

typedef int (*pfn_UserHasLicenseForApp_flat)(void *self, uint64_t steamID, uint32_t appID);
static pfn_UserHasLicenseForApp_flat Orig_UserHasLicenseForApp_flat = nullptr;

static uint64_t SelectSteamID(uint64_t origSteamID) {
	if (!g_hasConfiguredSteamID && origSteamID != 0)
		g_fakeSteamID = origSteamID;
	return g_fakeSteamID;
}

static bool Hooked_SteamAPI_RestartAppIfNecessary(uint32_t unOwnAppID) {
	g_mainAppId = unOwnAppID;
	LOG("[DSE-DLL] SteamAPI_RestartAppIfNecessary(%u) -> false\n", unOwnAppID);
	return false;
}

static uint64_t Hooked_GetSteamID(void *self) {
	uint64_t orig = Orig_GetSteamID ? Orig_GetSteamID(self) : 0;
	uint64_t ret = SelectSteamID(orig);
	LOG("[DSE-DLL] SteamAPI_ISteamUser_GetSteamID orig=%llu -> %llu\n",
		(unsigned long long)orig, (unsigned long long)ret);
	return ret;
}

static bool Hooked_BLoggedOn(void *self) {
	bool orig = Orig_BLoggedOn ? Orig_BLoggedOn(self) : false;
	bool ret = g_forceOffline ? false : orig;
	LOG("[DSE-DLL] SteamAPI_ISteamUser_BLoggedOn orig=%d -> %d\n", orig, ret);
	return ret;
}

static int Hooked_GetPersonaState(void *self) {
	int orig = Orig_GetPersonaState ? Orig_GetPersonaState(self) : 0;
	int ret = g_forceOffline ? 0 : orig;
	LOG("[DSE-DLL] SteamAPI_ISteamFriends_GetPersonaState orig=%d -> %d\n",
		orig, ret);
	return ret;
}

static int Hooked_UserHasLicenseForApp_flat(void *self, uint64_t steamID, uint32_t appID) {
	(void)self;
	LOG("[DSE-DLL] SteamAPI_ISteamUser_UserHasLicenseForApp(%llu, %u) -> HasLicense\n",
		(unsigned long long)steamID, appID);
	return 0;
}

typedef uint32_t (*pfn_GetAppOwnershipTicketData_flat)(void *self, uint32_t nAppId, void *pvBuffer, uint32_t cbBufferLength, uint32_t *piAppId, uint32_t *piSteamId, uint32_t *piSignature, uint32_t *pcbSignature);
static pfn_GetAppOwnershipTicketData_flat Orig_GetAppOwnershipTicketData_flat = nullptr;

static void HookSteamInterfaceByVersion(void *pInterface, const char *pszVersion);
static void HookInterface_ISteamApps(void *pInterface, const char *pszVersion);

static uint32_t BuildAppTicketData(uint32_t nAppId, void *pvBuffer, uint32_t cbBufferLength, uint32_t *piAppId, uint32_t *piSteamId, uint32_t *piSignature, uint32_t *pcbSignature) {
	if (!pvBuffer || cbBufferLength < 24) {
		LOG("[DSE-DLL] BuildAppTicketData failed (bad buffer or len < 24)\n");
		return 0;
	}

	memset(pvBuffer, 0, 24); // Ensure all bytes are initialized

	*(uint32_t *)((uintptr_t)pvBuffer + 0) = nAppId;
	uint64_t steamId = SelectSteamID(g_fakeSteamID);
	*(uint64_t *)((uintptr_t)pvBuffer + 8) = (uint64_t)steamId;
	// Next 8 bytes (16-23) remain 0

	if (piAppId)
		*piAppId = 0;
	if (piSteamId)
		*piSteamId = 8;
	if (piSignature)
		*piSignature = 16;
	if (pcbSignature)
		*pcbSignature = 8;

	LOG("[DSE-DLL] BuildAppTicketData -> appId=%u steamId=%llu offsets: appId=%u steamId=%u sig=%u cbSig=%u\n",
		nAppId, (unsigned long long)steamId,
		piAppId ? *piAppId : 0,
		piSteamId ? *piSteamId : 0,
		piSignature ? *piSignature : 0,
		pcbSignature ? *pcbSignature : 0);

	return 24;
}

static uint32_t Hooked_GetAppOwnershipTicketData_flat(void *self, uint32_t nAppId, void *pvBuffer, uint32_t cbBufferLength, uint32_t *piAppId, uint32_t *piSteamId, uint32_t *piSignature, uint32_t *pcbSignature) {
	(void)self;
	return BuildAppTicketData(nAppId, pvBuffer, cbBufferLength, piAppId, piSteamId, piSignature, pcbSignature);
}

static bool CheckAppSubscribed(uint32_t appId) {
	if (g_mainAppId != 0 && appId == g_mainAppId)
		return true;
	char szEnv[32]{};
	if (GetEnvironmentVariableA("SteamAppId", szEnv, sizeof(szEnv))) {
		uint32_t envAppId = (uint32_t)atoi(szEnv);
		if (envAppId != 0 && appId == envAppId)
			return true;
	}
	if (g_unlockAllDlcs)
		return true;
	for (const auto &dlc : g_unlockedDlcs) {
		if (dlc.appId == appId)
			return true;
	}
	return false;
}

static bool IsSteamAppsInterfaceVersion(const char *pszVersion) {
	return pszVersion &&
		   (strncmp(pszVersion, "STEAMAPPS_INTERFACE_VERSION", 27) == 0 ||
			strncmp(pszVersion, "SteamApps0", 10) == 0);
}

typedef void *(*pfn_ISteamClient_GetISteamGenericInterface_flat)(void *self, int32_t hSteamUser, int32_t hSteamPipe, const char *pchVersion);
static pfn_ISteamClient_GetISteamGenericInterface_flat Orig_ISteamClient_GetISteamGenericInterface_flat = nullptr;

static void *Hooked_ISteamClient_GetISteamGenericInterface_flat(void *self, int32_t hSteamUser, int32_t hSteamPipe, const char *pchVersion) {
	void *p = Orig_ISteamClient_GetISteamGenericInterface_flat
				  ? Orig_ISteamClient_GetISteamGenericInterface_flat(self, hSteamUser, hSteamPipe, pchVersion)
				  : nullptr;
	LOG("[DSE-DLL] SteamAPI_ISteamClient_GetISteamGenericInterface(%s, %d, %d) -> %p\n",
		pchVersion ? pchVersion : "(null)", hSteamUser, hSteamPipe, p);
	HookSteamInterfaceByVersion(p, pchVersion);
	return p;
}

typedef void *(*pfn_ISteamClient_GetISteamApps_flat)(void *self, int32_t hSteamUser, int32_t hSteamPipe, const char *pchVersion);
static pfn_ISteamClient_GetISteamApps_flat Orig_ISteamClient_GetISteamApps_flat = nullptr;

static void *Hooked_ISteamClient_GetISteamApps_flat(void *self, int32_t hSteamUser, int32_t hSteamPipe, const char *pchVersion) {
	void *p = Orig_ISteamClient_GetISteamApps_flat
				  ? Orig_ISteamClient_GetISteamApps_flat(self, hSteamUser, hSteamPipe, pchVersion)
				  : nullptr;
	LOG("[DSE-DLL] SteamAPI_ISteamClient_GetISteamApps(%s, %d, %d) -> %p\n",
		pchVersion ? pchVersion : "(null)", hSteamUser, hSteamPipe, p);
	HookInterface_ISteamApps(p, pchVersion);
	return p;
}

// VTable hooks
static void *Hooked_GetSteamID_vtable(void *self, uint64_t *pOut) {
	uint64_t localBuf = 0;
	uint64_t orig = 0;
	bool usedHiddenBuf = false;

	if (Orig_GetSteamID_vtable) {
		void *raw = Orig_GetSteamID_vtable(self, &localBuf);
		if (raw == (void *)&localBuf) {
			orig = localBuf;
			usedHiddenBuf = true;
		} else {
			orig = (uint64_t)(uintptr_t)raw;
		}
	}

	uint64_t ret = SelectSteamID(orig);

	static bool s_synced = false;
	if (!s_synced && orig != ret && orig != 0) {
		s_synced = true;
	}

	if (usedHiddenBuf && pOut)
		*pOut = ret;

	LOG("[DSE-DLL] ISteamUser::GetSteamID() orig=%llu -> %llu (caller=%p)\n",
		(unsigned long long)orig, (unsigned long long)ret, __builtin_return_address(0));

	return usedHiddenBuf ? pOut : (void *)(uintptr_t)ret;
}

typedef void *(*pfn_GetAppOwner_vtable)(void *self, uint64_t *pOut);
static pfn_GetAppOwner_vtable Orig_GetAppOwner_vtable = nullptr;

static void *Hooked_GetAppOwner_vtable(void *self, uint64_t *pOut) {
	uint64_t localBuf = 0;
	uint64_t orig = 0;
	bool usedHiddenBuf = false;

	if (Orig_GetAppOwner_vtable) {
		void *raw = Orig_GetAppOwner_vtable(self, &localBuf);
		if (raw == (void *)&localBuf) {
			orig = localBuf;
			usedHiddenBuf = true;
		} else {
			orig = (uint64_t)(uintptr_t)raw;
		}
	}

	uint64_t ret = SelectSteamID(orig);

	if (usedHiddenBuf && pOut)
		*pOut = ret;

	LOG("[DSE-DLL] ISteamApps::GetAppOwner() orig=%llu -> %llu (%s)\n",
		(unsigned long long)orig, (unsigned long long)ret,
		usedHiddenBuf ? "hidden-buf" : "direct-ret");

	return usedHiddenBuf ? pOut : (void *)(uintptr_t)ret;
}

static bool Hooked_BLoggedOn_vtable(void *self) {
	(void)self;
	bool ret = !g_forceOffline;
	LOG("[DSE-DLL] ISteamUser::BLoggedOn() -> %d\n", ret);
	return ret;
}

static int Hooked_GetPersonaState_vtable(void *self) {
	int orig = Orig_GetPersonaState_vtable ? Orig_GetPersonaState_vtable(self) : 0;
	int ret = g_forceOffline ? 0 : orig;
	LOG("[DSE-DLL] ISteamFriends::GetPersonaState() orig=%d -> %d\n", orig,
		ret);
	return ret;
}

static uint32_t Hooked_GetAppOwnershipTicketData_vtable(void *self, uint32_t nAppId, void *pvBuffer, uint32_t cbBufferLength, uint32_t *piAppId, uint32_t *piSteamId, uint32_t *piSignature, uint32_t *pcbSignature) {
	return BuildAppTicketData(nAppId, pvBuffer, cbBufferLength, piAppId, piSteamId, piSignature, pcbSignature);
}

static void HookInterface_ISteamUser(void *pInterface, const char *pszVersion);
static void HookInterface_ISteamFriends(void *pInterface);
static void HookInterface_ISteamAppTicket(void *pInterface);
static void HookInterface_ISteamApps(void *pInterface, const char *pszVersion);

static void HookSteamInterfaceByVersion(void *pInterface, const char *pszVersion) {
	if (!pInterface || !pszVersion)
		return;
	if (strncmp(pszVersion, "STEAMAPPTICKET", 14) == 0) {
		HookInterface_ISteamAppTicket(pInterface);
	} else if (strncmp(pszVersion, "SteamUser0", 10) == 0) {
		HookInterface_ISteamUser(pInterface, pszVersion);
	} else if (strncmp(pszVersion, "SteamFriends0", 13) == 0) {
		HookInterface_ISteamFriends(pInterface);
	} else if (strncmp(pszVersion, "SteamApps0", 10) == 0) {
		HookInterface_ISteamApps(pInterface, pszVersion);
	} else if (strncmp(pszVersion, "STEAMAPPS_INTERFACE_VERSION", 27) == 0) {
		HookInterface_ISteamApps(pInterface, pszVersion);
	}
}

#define HOOK_CLIENT_SLOT(slot)                                                                                                   \
	static void *(*Orig_ClientSlot##slot)(void *self, int32_t hSteamUser, int32_t hSteamPipe, const char *pchVersion) = nullptr; \
	static void *Hooked_ClientSlot##slot(void *self, int32_t hSteamUser, int32_t hSteamPipe, const char *pchVersion) {           \
		void *p = Orig_ClientSlot##slot ? Orig_ClientSlot##slot(self, hSteamUser, hSteamPipe, pchVersion) : nullptr;             \
		if (p && pchVersion) {                                                                                                   \
			LOG("[DSE-DLL] ISteamClient::Slot" #slot "(%s) -> %p\n", pchVersion, p);                                             \
			HookSteamInterfaceByVersion(p, pchVersion);                                                                          \
		}                                                                                                                        \
		return p;                                                                                                                \
	}

#define HOOK_CLIENT_UTILS_SLOT(slot)                                                                         \
	static void *(*Orig_ClientSlot##slot)(void *self, int32_t hSteamPipe, const char *pchVersion) = nullptr; \
	static void *Hooked_ClientSlot##slot(void *self, int32_t hSteamPipe, const char *pchVersion) {           \
		void *p = Orig_ClientSlot##slot ? Orig_ClientSlot##slot(self, hSteamPipe, pchVersion) : nullptr;     \
		LOG("[DSE-DLL] ISteamClient::Slot" #slot " (utils) -> %p\n", p);                                     \
		return p;                                                                                            \
	}

static void (*Orig_ClientSlot4)(void *self, int32_t hSteamPipe, int32_t hUser) = nullptr;
static void Hooked_ClientSlot4(void *self, int32_t hSteamPipe, int32_t hUser) {
	LOG("[DSE-DLL] ISteamClient::Slot4 (ReleaseUser) %d %d -> forwarded\n", hSteamPipe, hUser);
	if (Orig_ClientSlot4)
		Orig_ClientSlot4(self, hSteamPipe, hUser);
	LOG("[DSE-DLL] ISteamClient::Slot4 (ReleaseUser) -> forwarded SUCCESS\n");
}

static void (*Orig_SetCallbackCheck)(void *self, void *func) = nullptr;
static void Hooked_SetCallbackCheck(void *self, void *func) {
	LOG("[DSE-DLL] ISteamClient::Set_SteamAPI_CCheckCallbackRegisteredInProcess -> forwarded\n");
	if (Orig_SetCallbackCheck)
		Orig_SetCallbackCheck(self, func);
}

HOOK_CLIENT_SLOT(5);
HOOK_CLIENT_SLOT(8);
HOOK_CLIENT_UTILS_SLOT(9);
HOOK_CLIENT_SLOT(10);
HOOK_CLIENT_SLOT(11);
static uint32_t Fake_GetAppOwnershipTicketData(void *self, uint32_t nAppId, void *pvBuffer, uint32_t cbBufferLength, uint32_t *piAppId, uint32_t *piSteamId, uint32_t *piSignature, uint32_t *pcbSignature) {
	(void)self;
	return BuildAppTicketData(nAppId, pvBuffer, cbBufferLength, piAppId, piSteamId, piSignature, pcbSignature);
}

static void *g_FakeAppTicketVTable[] = {
	(void *)&Fake_GetAppOwnershipTicketData};
static void *g_pFakeAppTicket = &g_FakeAppTicketVTable;

static void *(*Orig_ClientSlot12)(void *self, int32_t hSteamUser, int32_t hSteamPipe, const char *pchVersion) = nullptr;
static void *Hooked_ClientSlot12(void *self, int32_t hSteamUser, int32_t hSteamPipe, const char *pchVersion) {
	if (pchVersion && strncmp(pchVersion, "STEAMAPPTICKET", 14) == 0) {
		LOG("[DSE-DLL] ISteamClient::Slot12 (GetISteamGenericInterface) %s -> returning fake AppTicket\n", pchVersion);
		return &g_pFakeAppTicket;
	}
	void *p = Orig_ClientSlot12 ? Orig_ClientSlot12(self, hSteamUser, hSteamPipe, pchVersion) : nullptr;
	LOG("[DSE-DLL] ISteamClient::Slot12 (GetISteamGenericInterface) %s -> %p\n", pchVersion, p);
	if (p && pchVersion)
		HookSteamInterfaceByVersion(p, pchVersion);
	return p;
}
HOOK_CLIENT_SLOT(13);
HOOK_CLIENT_SLOT(14);
HOOK_CLIENT_SLOT(15);
HOOK_CLIENT_SLOT(16);

typedef uint32_t (*pfn_GetEarliestPurchaseUnixTime_vtable)(void *self, uint32_t appID);
static pfn_GetEarliestPurchaseUnixTime_vtable Orig_GetEarliestPurchaseUnixTime_vtable = nullptr;

static uint32_t Hooked_GetEarliestPurchaseUnixTime_vtable(void *self, uint32_t appID) {
	(void)self;
	if (CheckAppSubscribed(appID)) {
		LOG("[DSE-DLL] ISteamApps::GetEarliestPurchaseUnixTime(%u) -> spoofed\n", appID);
		return 1700000000;
	}
	uint32_t orig = Orig_GetEarliestPurchaseUnixTime_vtable ? Orig_GetEarliestPurchaseUnixTime_vtable(self, appID) : 0;
	LOG("[DSE-DLL] ISteamApps::GetEarliestPurchaseUnixTime(%u) -> %u (original)\n", appID, orig);
	return orig;
}

typedef bool (*pfn_BIsDlcInstalled_vtable)(void *self, uint32_t appID);
static pfn_BIsDlcInstalled_vtable Orig_BIsDlcInstalled_vtable = nullptr;

typedef bool (*pfn_BIsSubscribedApp_vtable)(void *self, uint32_t appID);
static pfn_BIsSubscribedApp_vtable Orig_BIsSubscribedApp_vtable = nullptr;

static bool SteamApps_BIsSubscribedApp_Impl(uint32_t appID) {
	if (appID == 0) {
		LOG("[DSE-DLL] ISteamApps::BIsSubscribedApp(%u) -> false (zero)\n", appID);
		return false;
	}
	if (appID == 0xFFFFFFFF) {
		LOG("[DSE-DLL] ISteamApps::BIsSubscribedApp(%u) -> true (uint32_max)\n", appID);
		return true;
	}
	char szAppId[32] = {0};
	GetEnvironmentVariableA("SteamAppId", szAppId, sizeof(szAppId));
	uint32_t currentAppId = (uint32_t)atoi(szAppId);
	if (appID == currentAppId) {
		LOG("[DSE-DLL] ISteamApps::BIsSubscribedApp(%u) -> true (current app)\n", appID);
		return true;
	}
	if (CheckAppSubscribed(appID)) {
		LOG("[DSE-DLL] ISteamApps::BIsSubscribedApp(%u) -> true (subscribed)\n", appID);
		return true;
	}
	LOG("[DSE-DLL] ISteamApps::BIsSubscribedApp(%u) -> false (not found)\n", appID);
	return false;
}

typedef bool (*pfn_BIsSubscribedApp_flat)(void *self, uint32_t appID);
static pfn_BIsSubscribedApp_flat Orig_BIsSubscribedApp_flat = nullptr;

static bool Hooked_BIsSubscribedApp_flat(void *self, uint32_t appID) {
	(void)self;
	return SteamApps_BIsSubscribedApp_Impl(appID);
}

static bool Hooked_BIsSubscribedApp_vtable(void *self, uint32_t appID) {
	(void)self;
	return SteamApps_BIsSubscribedApp_Impl(appID);
}

static bool Hooked_BIsDlcInstalled_vtable(void *self, uint32_t appID) {
	(void)self;
	if (appID == 0)
		return false;
	if (g_unlockAllDlcs) {
		LOG("[DSE-DLL] ISteamApps::BIsDlcInstalled(%u) -> true (unlock_all)\n", appID);
		return true;
	}
	for (const auto &dlc : g_unlockedDlcs) {
		if (dlc.appId == appID) {
			LOG("[DSE-DLL] ISteamApps::BIsDlcInstalled(%u) -> true (in list)\n", appID);
			return true;
		}
	}
	LOG("[DSE-DLL] ISteamApps::BIsDlcInstalled(%u) -> false\n", appID);
	return false;
}

static bool (*Orig_BIsSubscribed_vtable)(void *self) = nullptr;
static bool Hooked_BIsSubscribed_vtable(void *self) {
	(void)self;
	LOG("[DSE-DLL] ISteamApps::BIsSubscribed() -> true (spoofed)\n");
	return true;
}

static bool (*Orig_BIsAppInstalled_vtable)(void *self, uint32_t appID) = nullptr;
static bool Hooked_BIsAppInstalled_vtable(void *self, uint32_t appID) {
	(void)self;
	LOG("[DSE-DLL] ISteamApps::BIsAppInstalled(%u) -> true (spoofed)\n", appID);
	return true;
}

typedef int (*pfn_GetDLCCount_vtable)(void *self);
static pfn_GetDLCCount_vtable Orig_GetDLCCount_vtable = nullptr;

static int Hooked_GetDLCCount_vtable(void *self) {
	(void)self;
	int count = (int)g_unlockedDlcs.size();
	LOG("[DSE-DLL] ISteamApps::GetDLCCount() -> %d (spoofed)\n", count);
	return count;
}

typedef bool (*pfn_BGetDLCDataByIndex_vtable)(void *self, int iDLC, uint32_t *pAppID, bool *pbAvailable, char *pchName, int cchNameBufferSize);
static pfn_BGetDLCDataByIndex_vtable Orig_BGetDLCDataByIndex_vtable = nullptr;

static bool Hooked_BGetDLCDataByIndex_vtable(void *self, int iDLC, uint32_t *pAppID, bool *pbAvailable, char *pchName, int cchNameBufferSize) {
	(void)self;
	if (iDLC >= 0 && iDLC < (int)g_unlockedDlcs.size()) {
		const auto &dlc = g_unlockedDlcs[iDLC];
		if (pAppID)
			*pAppID = dlc.appId;
		if (pbAvailable)
			*pbAvailable = true;
		if (pchName && cchNameBufferSize > 0) {
			memset(pchName, 0, cchNameBufferSize);
			lstrcpynA(pchName, dlc.name, cchNameBufferSize);
		}
		LOG("[DSE-DLL] ISteamApps::BGetDLCDataByIndex(%d) -> spoofed AppId=%u\n", iDLC, dlc.appId);
		return true;
	}
	return false;
}

// Interface hookers
static int ParseSteamUserVersion(const char *pszVersion) {
	if (!pszVersion)
		return 0;
	const char *p = nullptr;
	if (strncmp(pszVersion, "SteamUser", 9) == 0)
		p = pszVersion + 9;
	if (!p)
		return 0;
	int ver = 0;
	while (*p >= '0' && *p <= '9') {
		ver = ver * 10 + (*p - '0');
		++p;
	}
	return ver;
}

static bool ResolveSteamUserSlots(const char *pszVersion, int &loggedOnSlot, int &getIDSlot) {
	int ver = ParseSteamUserVersion(pszVersion);
	if (ver >= 8) {
		loggedOnSlot = 1;
		getIDSlot = 2;
		return true;
	}
	if (ver >= 6) {
		loggedOnSlot = 3;
		getIDSlot = 4;
		return true;
	}
	if (ver == 5) {
		loggedOnSlot = 3;
		getIDSlot = 6;
		return true;
	}
	if (ver >= 1 && ver <= 4) {
		loggedOnSlot = 4;
		getIDSlot = -1;
		return true;
	}
	loggedOnSlot = 1;
	getIDSlot = 2;
	return false;
}

static int ResolveSteamUserLicenseSlot(const char *pszVersion) {
	int ver = ParseSteamUserVersion(pszVersion);
	if (ver >= 23)
		return 18;
	if (ver >= 15)
		return 17;
	if (ver >= 13)
		return 16;
	if (ver == 12)
		return 15;
	return -1;
}

static void SwapVTable(void *pInterface, void ***pFakeVTableOut, void ***pRealVTableOut, void **staticBuffer) {
	void **vtable = *(void ***)pInterface;
	if (*pFakeVTableOut && vtable == *pFakeVTableOut)
		return;

	*pRealVTableOut = vtable;

	void **fakeVTable = &staticBuffer[2];

	// Copy RTTI metadata and the VTable itself
	fakeVTable[-2] = vtable[-2]; // Sometimes useful
	fakeVTable[-1] = vtable[-1]; // RTTI CompleteObjectLocator
	memcpy(fakeVTable, vtable, sizeof(void *) * 100);

	DWORD oldProtect;
	VirtualProtect(pInterface, sizeof(void *), PAGE_EXECUTE_READWRITE, &oldProtect);
	*(void ***)pInterface = fakeVTable;
	VirtualProtect(pInterface, sizeof(void *), oldProtect, &oldProtect);

	*pFakeVTableOut = fakeVTable;
	LOG("[DSE-DLL] VTable swapped object at %p\n", pInterface);
}

static void TryHookVTableSlot_Swap(void **fakeVTable, void **realVTable, int slot, LPVOID detour, LPVOID *orig, const char *name) {
	if (!realVTable || slot < 0 || !realVTable[slot])
		return;

	if (orig)
		*orig = realVTable[slot];
	fakeVTable[slot] = detour;
	LOG("[DSE-DLL]   Swapped %s slot [%d] @ %p -> %p\n", name, slot, realVTable[slot], detour);
}

static void TryHookUserSlot(void **vtable, int slot, LPVOID detour, LPVOID *orig, const char *name) {
	if (!vtable || slot < 0 || !vtable[slot])
		return;
	LPVOID tempOrig = nullptr;
	MH_STATUS status = MH_CreateHook(vtable[slot], detour, &tempOrig);
	if (status == MH_OK) {
		if (orig)
			*orig = tempOrig;
		MH_EnableHook(vtable[slot]);
		LOG("[DSE-DLL]   Hooked %s slot [%d] @ %p\n", name, slot, vtable[slot]);
	} else if (status == MH_ERROR_ALREADY_CREATED) {
		MH_EnableHook(vtable[slot]);
		LOG("[DSE-DLL]   %s slot [%d] @ %p already hooked\n", name, slot, vtable[slot]);
	} else {
		LOG("[DSE-DLL]   Failed to hook %s slot [%d] @ %p: %s\n",
			name, slot, vtable[slot], MH_StatusToString(status));
	}
}

static void **g_pFakeSteamUserVTable = nullptr;
static void *g_FakeSteamUserVTableBuffer[102];

static void HookInterface_ISteamUser(void *pInterface, const char *pszVersion) {
	if (!pInterface)
		return;

	void **realVTable = nullptr;
	SwapVTable(pInterface, &g_pFakeSteamUserVTable, &realVTable, g_FakeSteamUserVTableBuffer);
	if (!realVTable)
		return;

	if (g_pISteamUserVTable == realVTable)
		return;
	g_pISteamUserVTable = realVTable;

	int loggedOnSlot = 1;
	int getIDSlot = 2;
	int userHasLicenseSlot = ResolveSteamUserLicenseSlot(pszVersion);
	bool versionKnown = ResolveSteamUserSlots(pszVersion, loggedOnSlot, getIDSlot);

	LOG("[DSE-DLL] Intercepted ISteamUser vtable at %p (%s, layout=%s)\n",
		realVTable, pszVersion ? pszVersion : "unknown", versionKnown ? "versioned" : "fallback");
	for (int i = 0; i < 16; i++)
		LOG("[DSE-DLL]   vtable[%d] = %p\n", i, realVTable[i]);
	LOG("[DSE-DLL]   BLoggedOn  -> slot [%d] (%s)\n", loggedOnSlot,
		versionKnown ? "from version" : "fallback");
	if (getIDSlot >= 0)
		LOG("[DSE-DLL]   GetSteamID -> slot [%d] (%s)\n", getIDSlot,
			versionKnown ? "from version" : "fallback");
	else
		LOG("[DSE-DLL]   GetSteamID -> not present in %s\n",
			pszVersion ? pszVersion : "this interface");
	if (userHasLicenseSlot >= 0)
		LOG("[DSE-DLL]   UserHasLicenseForApp -> slot [%d]\n", userHasLicenseSlot);
	else
		LOG("[DSE-DLL]   UserHasLicenseForApp -> not present in %s\n",
			pszVersion ? pszVersion : "this interface");

	TryHookVTableSlot_Swap(g_pFakeSteamUserVTable, realVTable, loggedOnSlot, (LPVOID)&Hooked_BLoggedOn_vtable,
						   (LPVOID *)&Orig_BLoggedOn_vtable, "ISteamUser::BLoggedOn");
	TryHookVTableSlot_Swap(g_pFakeSteamUserVTable, realVTable, getIDSlot, (LPVOID)&Hooked_GetSteamID_vtable,
						   (LPVOID *)&Orig_GetSteamID_vtable, "ISteamUser::GetSteamID");
}

static void **g_pFakeSteamFriendsVTable = nullptr;
static void *g_FakeSteamFriendsVTableBuffer[102];

static void HookInterface_ISteamFriends(void *pInterface) {
	if (!pInterface)
		return;

	void **realVTable = nullptr;
	SwapVTable(pInterface, &g_pFakeSteamFriendsVTable, &realVTable, g_FakeSteamFriendsVTableBuffer);
	if (!realVTable)
		return;

	if (g_pISteamFriendsVTable == realVTable)
		return;
	g_pISteamFriendsVTable = realVTable;
	LOG("[DSE-DLL] Intercepted ISteamFriends vtable at %p\n", realVTable);

	TryHookVTableSlot_Swap(g_pFakeSteamFriendsVTable, realVTable, 2, (LPVOID)&Hooked_GetPersonaState_vtable,
						   (LPVOID *)&Orig_GetPersonaState_vtable, "ISteamFriends::GetPersonaState");
}

static void **g_pISteamAppTicketVTable = nullptr;
static void **g_pFakeSteamAppTicketVTable = nullptr;
static void *g_FakeSteamAppTicketVTableBuffer[102];

static void HookInterface_ISteamAppTicket(void *pInterface) {
	if (!pInterface)
		return;

	void **realVTable = nullptr;
	SwapVTable(pInterface, &g_pFakeSteamAppTicketVTable, &realVTable, g_FakeSteamAppTicketVTableBuffer);
	if (!realVTable)
		return;

	static bool g_steamAppTicketHooked = false;
	if (g_pISteamAppTicketVTable != realVTable) {
		g_pISteamAppTicketVTable = realVTable;
		LOG("[DSE-DLL] Intercepted ISteamAppTicket vtable at %p\n", realVTable);
	}
	if (!g_steamAppTicketHooked && g_pFakeSteamAppTicketVTable && realVTable[0]) {
		TryHookVTableSlot_Swap(g_pFakeSteamAppTicketVTable, realVTable, 0, (LPVOID)&Hooked_GetAppOwnershipTicketData_vtable,
							   (LPVOID *)&Orig_GetAppOwnershipTicketData_vtable, "ISteamAppTicket::GetAppOwnershipTicketData");
		g_steamAppTicketHooked = true;
	}
}

static void **g_pISteamAppsVTable = nullptr;
static int g_steamAppsVersion = 0;
static void **g_pFakeSteamAppsVTable = nullptr;
static void *g_FakeSteamAppsVTableBuffer[102];

static void TryHookVTableSlot(void **vtable, int slot, LPVOID detour, LPVOID *orig, const char *name) {
	if (!vtable || slot < 0 || !vtable[slot])
		return;
	MH_STATUS status = MH_CreateHook(vtable[slot], detour, orig);
	if (status == MH_OK || status == MH_ERROR_ALREADY_CREATED) {
		MH_EnableHook(vtable[slot]);
		LOG("[DSE-DLL]   Hooked %s slot [%d] @ %p (%s)\n", name, slot, vtable[slot], MH_StatusToString(status));
	} else {
		LOG("[DSE-DLL]   Failed to hook %s slot [%d] @ %p: %s\n", name, slot, vtable[slot], MH_StatusToString(status));
	}
}

static int ParseSteamAppsVersion(const char *pszVersion) {
	if (!pszVersion)
		return 0;
	const char *p = nullptr;
	if (strncmp(pszVersion, "STEAMAPPS_INTERFACE_VERSION", 27) == 0)
		p = pszVersion + 27;
	else if (strncmp(pszVersion, "SteamApps", 9) == 0)
		p = pszVersion + 9;
	if (!p)
		return 0;
	int ver = 0;
	while (*p >= '0' && *p <= '9') {
		ver = (ver * 10) + (*p - '0');
		++p;
	}
	return ver;
}

static void HookInterface_ISteamApps(void *pInterface, const char *pszVersion) {
	if (!pInterface)
		return;

	void **realVTable = g_pISteamAppsVTable; // Important to preserve existing realVTable
	SwapVTable(pInterface, &g_pFakeSteamAppsVTable, &realVTable, g_FakeSteamAppsVTableBuffer);
	if (!realVTable)
		return;

	int ver = ParseSteamAppsVersion(pszVersion);
	if (g_pISteamAppsVTable != realVTable) {
		g_pISteamAppsVTable = realVTable;
		LOG("[DSE-DLL] Intercepted ISteamApps vtable at %p (ver=%d)\n", realVTable, ver);
	} else if (ver > g_steamAppsVersion) {
		g_steamAppsVersion = ver;
	}

	if (ver >= 2)
		TryHookVTableSlot(realVTable, 0, (LPVOID)&Hooked_BIsSubscribed_vtable,
						  (LPVOID *)&Orig_BIsSubscribed_vtable,
						  "ISteamApps::BIsSubscribed");

	if (ver >= 2)
		TryHookVTableSlot(realVTable, 6, (LPVOID)&Hooked_BIsSubscribedApp_vtable,
						  (LPVOID *)&Orig_BIsSubscribedApp_vtable,
						  "ISteamApps::BIsSubscribedApp");

	if (ver >= 2)
		TryHookVTableSlot(realVTable, 7, (LPVOID)&Hooked_BIsDlcInstalled_vtable,
						  (LPVOID *)&Orig_BIsDlcInstalled_vtable,
						  "ISteamApps::BIsDlcInstalled");

	if (ver >= 3) {
		TryHookVTableSlot(realVTable, 8, (LPVOID)&Hooked_GetEarliestPurchaseUnixTime_vtable,
						  (LPVOID *)&Orig_GetEarliestPurchaseUnixTime_vtable,
						  "ISteamApps::GetEarliestPurchaseUnixTime");
	}

	if (ver >= 4) {
		TryHookVTableSlot(realVTable, 10, (LPVOID)&Hooked_GetDLCCount_vtable,
						  (LPVOID *)&Orig_GetDLCCount_vtable,
						  "ISteamApps::GetDLCCount");

		TryHookVTableSlot(realVTable, 11, (LPVOID)&Hooked_BGetDLCDataByIndex_vtable,
						  (LPVOID *)&Orig_BGetDLCDataByIndex_vtable,
						  "ISteamApps::BGetDLCDataByIndex");
	}

	if (ver >= 6) {
		TryHookVTableSlot(realVTable, 19, (LPVOID)&Hooked_BIsAppInstalled_vtable,
						  (LPVOID *)&Orig_BIsAppInstalled_vtable,
						  "ISteamApps::BIsAppInstalled");
	}

	if (ver >= 8) {
		TryHookVTableSlot(realVTable, 20, (LPVOID)&Hooked_GetAppOwner_vtable,
						  (LPVOID *)&Orig_GetAppOwner_vtable,
						  "ISteamApps::GetAppOwner");
	}
}

static void **g_pISteamClientVTable = nullptr;
static void HookInterface_ISteamClient(void *pInterface, const char *pszVersion) {
	if (!pInterface)
		return;
	void **vtable = *(void ***)pInterface;
	if (g_pISteamClientVTable == vtable)
		return;
	g_pISteamClientVTable = vtable;
	LOG("[DSE-DLL] Intercepted ISteamClient vtable at %p (%s)\n", vtable, pszVersion ? pszVersion : "unknown");

	int ver = 0;
	if (pszVersion && strncmp(pszVersion, "SteamClient0", 12) == 0) {
		ver = atoi(pszVersion + 12);
	}

#define APPLY_CLIENT_HOOK(slot)                                                                        \
	MH_CreateHook(vtable[slot], (LPVOID) & Hooked_ClientSlot##slot, (LPVOID *)&Orig_ClientSlot##slot); \
	MH_EnableHook(vtable[slot])

	APPLY_CLIENT_HOOK(4); // ReleaseUser
	APPLY_CLIENT_HOOK(5); // GetISteamUser
	APPLY_CLIENT_HOOK(8);
	APPLY_CLIENT_HOOK(9);
	APPLY_CLIENT_HOOK(10);
	APPLY_CLIENT_HOOK(11);
	APPLY_CLIENT_HOOK(12);
	APPLY_CLIENT_HOOK(13);
	APPLY_CLIENT_HOOK(14);
	APPLY_CLIENT_HOOK(15);
	APPLY_CLIENT_HOOK(16);

	int callbackSlot = -1;
	if (ver == 16)
		callbackSlot = 34;
	else if (ver == 17)
		callbackSlot = 33;
	else if (ver == 18)
		callbackSlot = 34;
	else if (ver == 19)
		callbackSlot = 34;
	else if (ver == 20)
		callbackSlot = 34;
	else if (ver == 21)
		callbackSlot = 32;
	else if (ver == 22)
		callbackSlot = 31;

	if (callbackSlot != -1) {
		TryHookVTableSlot(vtable, callbackSlot, (LPVOID)&Hooked_SetCallbackCheck, (LPVOID *)&Orig_SetCallbackCheck, "ISteamClient::Set_SteamAPI_CCheckCallbackRegisteredInProcess");
	}

#undef APPLY_CLIENT_HOOK
}

static void *
Hooked_SteamInternal_FindOrCreateUserInterface(int32_t hSteamUser,
											   const char *pszVersion) {
	void *p = Orig_FindOrCreateUserInterface
				  ? Orig_FindOrCreateUserInterface(hSteamUser, pszVersion)
				  : nullptr;
	if (!p || !pszVersion)
		return p;
	if (strncmp(pszVersion, "SteamUser0", 10) == 0)
		HookInterface_ISteamUser(p, pszVersion);
	else if (strncmp(pszVersion, "SteamFriends0", 13) == 0)
		HookInterface_ISteamFriends(p);
	else if (strncmp(pszVersion, "STEAMAPPTICKET", 14) == 0)
		HookInterface_ISteamAppTicket(p);
	else if (strncmp(pszVersion, "SteamApps0", 10) == 0)
		HookInterface_ISteamApps(p, pszVersion);
	else if (strncmp(pszVersion, "STEAMAPPS_INTERFACE_VERSION", 27) == 0)
		HookInterface_ISteamApps(p, pszVersion);
	return p;
}

static void *
Hooked_SteamInternal_CreateInterface(const char *pszVersion) {
	void *p = Orig_SteamInternal_CreateInterface
				  ? Orig_SteamInternal_CreateInterface(pszVersion)
				  : nullptr;
	if (!p || !pszVersion)
		return p;
	if (strncmp(pszVersion, "SteamClient0", 12) == 0)
		HookInterface_ISteamClient(p, pszVersion);
	return p;
}

static int32_t Hooked_SteamAPI_GetHSteamUser() {
	int32_t hUser = Orig_GetHSteamUser ? Orig_GetHSteamUser() : 0;
	LOG("[DSE-DLL] SteamAPI_GetHSteamUser() = %d\n", hUser);
	if (hUser && Orig_FindOrCreateUserInterface && !g_pISteamUserVTable) {
		const char *versions[] = {"SteamUser023", "SteamUser022", "SteamUser021",
								  "SteamUser020", "SteamUser019", nullptr};
		for (int i = 0; versions[i]; i++) {
			void *pUser = Orig_FindOrCreateUserInterface(hUser, versions[i]);
			if (pUser) {
				LOG("[DSE-DLL] Force-hooking ISteamUser via %s @ %p\n", versions[i],
					pUser);
				HookInterface_ISteamUser(pUser, versions[i]);
				break;
			}
		}
	}
	if (hUser && Orig_SteamInternal_CreateInterface && !g_pISteamClientVTable) {
		const char *client_versions[] = {"SteamClient021", "SteamClient020", "SteamClient019", "SteamClient018", "SteamClient017", nullptr};
		for (int i = 0; client_versions[i]; i++) {
			void *pClient = Orig_SteamInternal_CreateInterface(client_versions[i]);
			if (pClient) {
				LOG("[DSE-DLL] Force-hooking ISteamClient via %s @ %p\n", client_versions[i], pClient);
				HookInterface_ISteamClient(pClient, client_versions[i]);
				break;
			}
		}
	}
	return hUser;
}

#define HOOK_STEAMUSER(ver)                                              \
	typedef void *(*pfn_SteamUser##ver)();                               \
	static pfn_SteamUser##ver Orig_SteamUser##ver = nullptr;             \
	static void *Hooked_SteamUser##ver() {                               \
		void *p = Orig_SteamUser##ver ? Orig_SteamUser##ver() : nullptr; \
		HookInterface_ISteamUser(p, "SteamUser" #ver);                   \
		return p;                                                        \
	}

HOOK_STEAMUSER(015);
HOOK_STEAMUSER(016);
HOOK_STEAMUSER(017);
HOOK_STEAMUSER(018);
HOOK_STEAMUSER(019);
HOOK_STEAMUSER(020);
HOOK_STEAMUSER(021);
HOOK_STEAMUSER(022);
HOOK_STEAMUSER(023);
HOOK_STEAMUSER(024);
HOOK_STEAMUSER(025);

#define HOOK_STEAMFRIENDS(ver)                                                 \
	typedef void *(*pfn_SteamFriends##ver)();                                  \
	static pfn_SteamFriends##ver Orig_SteamFriends##ver = nullptr;             \
	static void *Hooked_SteamFriends##ver() {                                  \
		void *p = Orig_SteamFriends##ver ? Orig_SteamFriends##ver() : nullptr; \
		HookInterface_ISteamFriends(p);                                        \
		return p;                                                              \
	}

HOOK_STEAMFRIENDS(010);
HOOK_STEAMFRIENDS(011);
HOOK_STEAMFRIENDS(012);
HOOK_STEAMFRIENDS(013);
HOOK_STEAMFRIENDS(014);
HOOK_STEAMFRIENDS(015);
HOOK_STEAMFRIENDS(016);
HOOK_STEAMFRIENDS(017);
HOOK_STEAMFRIENDS(018);
HOOK_STEAMFRIENDS(019);
HOOK_STEAMFRIENDS(020);

#define HOOK_STEAMAPPS(ver)                                              \
	typedef void *(*pfn_SteamApps##ver)();                               \
	static pfn_SteamApps##ver Orig_SteamApps##ver = nullptr;             \
	static void *Hooked_SteamApps##ver() {                               \
		void *p = Orig_SteamApps##ver ? Orig_SteamApps##ver() : nullptr; \
		HookInterface_ISteamApps(p, "STEAMAPPS_INTERFACE_VERSION" #ver); \
		return p;                                                        \
	}

HOOK_STEAMAPPS(001);
HOOK_STEAMAPPS(002);
HOOK_STEAMAPPS(003);
HOOK_STEAMAPPS(004);
HOOK_STEAMAPPS(005);
HOOK_STEAMAPPS(006);
HOOK_STEAMAPPS(007);
HOOK_STEAMAPPS(008);
HOOK_STEAMAPPS(009);

#define HOOK_STEAMCLIENT(ver)                                                \
	typedef void *(*pfn_SteamClient##ver)();                                 \
	static pfn_SteamClient##ver Orig_SteamClient##ver = nullptr;             \
	static void *Hooked_SteamClient##ver() {                                 \
		void *p = Orig_SteamClient##ver ? Orig_SteamClient##ver() : nullptr; \
		HookInterface_ISteamClient(p, "SteamClient" #ver);                   \
		return p;                                                            \
	}

HOOK_STEAMCLIENT(010);
HOOK_STEAMCLIENT(011);
HOOK_STEAMCLIENT(012);
HOOK_STEAMCLIENT(013);
HOOK_STEAMCLIENT(014);
HOOK_STEAMCLIENT(015);
HOOK_STEAMCLIENT(016);
HOOK_STEAMCLIENT(017);
HOOK_STEAMCLIENT(018);
HOOK_STEAMCLIENT(019);
HOOK_STEAMCLIENT(020);
HOOK_STEAMCLIENT(021);

static void PreHookSingletons() {
	HMODULE hSteamApi = GetModuleHandleW(L"steam_api64.dll");
	if (!hSteamApi)
		hSteamApi = GetModuleHandleW(L"steam_api.dll");
	if (!hSteamApi)
		return;

	typedef int32_t (*pfn_SteamAPI_GetHSteamUser)();
	pfn_SteamAPI_GetHSteamUser pGetHSteamUser = (pfn_SteamAPI_GetHSteamUser)GetProcAddress(hSteamApi, "SteamAPI_GetHSteamUser");
	int32_t hUser = pGetHSteamUser ? pGetHSteamUser() : 0;

	if (hUser > 0 && Orig_FindOrCreateUserInterface) {
		void *pApps = Orig_FindOrCreateUserInterface(hUser, "STEAMAPPS_INTERFACE_VERSION008");
		if (pApps) {
			LOG("[DSE-DLL] Pre-hooking ISteamApps at %p\n", pApps);
			HookInterface_ISteamApps(pApps, "STEAMAPPS_INTERFACE_VERSION008");
		}
		void *pTicket = Orig_FindOrCreateUserInterface(hUser, "STEAMAPPTICKET_INTERFACE_VERSION001");
		if (pTicket) {
			LOG("[DSE-DLL] Pre-hooking ISteamAppTicket at %p\n", pTicket);
			HookInterface_ISteamAppTicket(pTicket);
		}
		void *pUser = Orig_FindOrCreateUserInterface(hUser, "SteamUser021");
		if (pUser) {
			LOG("[DSE-DLL] Pre-hooking ISteamUser at %p\n", pUser);
			HookInterface_ISteamUser(pUser, "SteamUser021");
		}
	} else {
		typedef void *(*pfn_SteamApps)();
		pfn_SteamApps pSteamApps = (pfn_SteamApps)GetProcAddress(hSteamApi, "SteamApps");
		if (pSteamApps) {
			void *pApps = pSteamApps();
			if (pApps) {
				LOG("[DSE-DLL] Pre-hooking ISteamApps via SteamApps()\n");
				HookInterface_ISteamApps(pApps, "STEAMAPPS_INTERFACE_VERSION008");
			}
		}
	}
}

static bool Hooked_SteamAPI_Init() {
	LOG("[DSE-DLL] SteamAPI_Init()\n");
	if (Orig_SteamAPI_Init) {
		bool r = Orig_SteamAPI_Init();
		if (r) {
			LOG("[DSE-DLL]   (real init succeeded)\n");
			PreHookSingletons();
		} else {
			LOG("[DSE-DLL]   (real init failed)\n");
		}
		return r;
	}
	return false;
}

static int Hooked_SteamAPI_InitFlat(char *pOutErrMsg) {
	LOG("[DSE-DLL] SteamAPI_InitFlat()\n");
	if (Orig_SteamAPI_InitFlat) {
		int r = Orig_SteamAPI_InitFlat(pOutErrMsg);
		if (r == 0) {
			LOG("[DSE-DLL]   (real InitFlat succeeded)\n");
			PreHookSingletons();
		} else {
			LOG("[DSE-DLL]   (real InitFlat failed with code %d)\n", r);
		}
		return r;
	}
	return 1;
}

static int Hooked_SteamInternal_SteamAPI_Init(const char *pszVersions,
											  char *pOutErrMsg) {
	LOG("[DSE-DLL] SteamInternal_SteamAPI_Init()\n");
	if (Orig_SteamInternal_Init) {
		int r = Orig_SteamInternal_Init(pszVersions, pOutErrMsg);
		if (r == 0) {
			LOG("[DSE-DLL]   (real internal init succeeded)\n");
			PreHookSingletons();
		} else {
			LOG("[DSE-DLL]   (real internal init failed with code %d)\n", r);
		}
		return r;
	}
	return 1;
}

static bool Hooked_IsSteamRunning() {
	bool orig = Orig_IsSteamRunning ? Orig_IsSteamRunning() : false;
	LOG("[DSE-DLL] SteamAPI_IsSteamRunning() orig=%d -> true\n", orig);
	return true;
}

static const char *Hooked_GetSteamInstallPath() {
	if (g_steamPath[0]) {
		LOG("[DSE-DLL] SteamAPI_GetSteamInstallPath() -> %s\n", g_steamPath);
		return g_steamPath;
	}
	if (Orig_GetSteamInstallPath) {
		const char *p = Orig_GetSteamInstallPath();
		LOG("[DSE-DLL] SteamAPI_GetSteamInstallPath() -> %s (original)\n",
			p ? p : "(null)");
		return p;
	}
	return "";
}

static void ResolveSteamPath() {
	if (g_steamPath[0])
		return;
	HKEY hKey = nullptr;
	if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Valve\\Steam", 0, KEY_READ,
					  &hKey) == ERROR_SUCCESS) {
		DWORD type = 0, size = MAX_PATH;
		char regPath[MAX_PATH]{};
		if (RegQueryValueExA(hKey, "SteamPath", nullptr, &type, (LPBYTE)regPath,
							 &size) == ERROR_SUCCESS)
			lstrcpynA(g_steamPath, regPath, MAX_PATH);
		RegCloseKey(hKey);
	}
	if (g_steamPath[0])
		LOG("[DSE-DLL] Steam path from registry: %s\n", g_steamPath);
	else
		LOG("[DSE-DLL] WARNING: Could not find Steam path!\n");
}

static void SetSteamEnvVars() {
	if (!g_steamPath[0])
		return;
	WCHAR wPath[MAX_PATH]{};
	MultiByteToWideChar(CP_UTF8, 0, g_steamPath, -1, wPath, MAX_PATH);
	SetEnvironmentVariableW(L"SteamPath", wPath);
	WCHAR clientPath[MAX_PATH]{};
	lstrcpynW(clientPath, wPath, MAX_PATH);
	PathAppendW(clientPath, L"steamclient64.dll");
	SetEnvironmentVariableW(L"SteamClientDll64", clientPath);
	SetDllDirectoryW(wPath);
	LOG("[DSE-DLL] Set SteamPath env = %s\n", g_steamPath);
}

static void HookSteamAPI(HMODULE hSteamApi) {
	static bool hooked = false;
	if (hooked)
		return;
	hooked = true;
	g_steamHooked = true;

	LOG("[DSE-DLL] steam_api64.dll detected @ %p - hooking...\n",
		(void *)hSteamApi);
	LoadSteamConfigFromDll(hSteamApi);
	ResolveSteamPath();
	SetSteamEnvVars();

#define TRY_IAT_HOOK(export, fn, orig, label)                                                  \
	do {                                                                                       \
		auto _p = (void *)GetProcAddress(hSteamApi, export);                                   \
		if (_p) {                                                                              \
			int _n = IATHookByAddress(_p, (void *)&fn, (void **)&orig);                        \
			RegisterIATHook(export, (void *)&fn, _p);                                          \
			if (_n > 0)                                                                        \
				LOG("[DSE-DLL]   IAT-hooked " label " (%d entries)\n", _n);                    \
			else                                                                               \
				LOG("[DSE-DLL]   " label " registered (no IAT, GetProcAddress will catch)\n"); \
		} else                                                                                 \
			LOG("[DSE-DLL]   " label " export not found\n");                                   \
	} while (0)

	WCHAR exeDir[MAX_PATH]{};
	GetModuleFileNameW(nullptr, exeDir, MAX_PATH);
	PathRemoveFileSpecW(exeDir);
	WCHAR reloadedAsiPath[MAX_PATH]{};
	lstrcpynW(reloadedAsiPath, exeDir, MAX_PATH);
	PathAppendW(reloadedAsiPath, L"Reloaded.Mod.Loader.Bootstrapper.asi");

	bool isReloaded = g_config.reloaded || (GetFileAttributesW(reloadedAsiPath) != INVALID_FILE_ATTRIBUTES);
	if (isReloaded) {
		LOG("[DSE-DLL] Reloaded-II detected or forced by config. Disabling specific Steam API hooks.\n");
	}

	if (!isReloaded) {
		TRY_IAT_HOOK("SteamAPI_RestartAppIfNecessary", Hooked_SteamAPI_RestartAppIfNecessary,
					 Orig_RestartApp, "SteamAPI_RestartAppIfNecessary");
	}
	TRY_IAT_HOOK("SteamAPI_ISteamUser_GetSteamID", Hooked_GetSteamID, Orig_GetSteamID,
				 "ISteamUser_GetSteamID");
	TRY_IAT_HOOK("SteamAPI_ISteamUser_BLoggedOn", Hooked_BLoggedOn, Orig_BLoggedOn,
				 "ISteamUser_BLoggedOn");
	TRY_IAT_HOOK("SteamAPI_ISteamUser_UserHasLicenseForApp", Hooked_UserHasLicenseForApp_flat,
				 Orig_UserHasLicenseForApp_flat, "ISteamUser_UserHasLicenseForApp");
	TRY_IAT_HOOK("SteamAPI_ISteamFriends_GetPersonaState", Hooked_GetPersonaState,
				 Orig_GetPersonaState, "ISteamFriends_GetPersonaState");
	TRY_IAT_HOOK("SteamAPI_ISteamAppTicket_GetAppOwnershipTicketData", Hooked_GetAppOwnershipTicketData_flat,
				 Orig_GetAppOwnershipTicketData_flat, "ISteamAppTicket_GetAppOwnershipTicketData");
	TRY_IAT_HOOK("SteamAPI_ISteamClient_GetISteamGenericInterface", Hooked_ISteamClient_GetISteamGenericInterface_flat,
				 Orig_ISteamClient_GetISteamGenericInterface_flat, "ISteamClient_GetISteamGenericInterface");
	TRY_IAT_HOOK("SteamAPI_ISteamClient_GetISteamApps", Hooked_ISteamClient_GetISteamApps_flat,
				 Orig_ISteamClient_GetISteamApps_flat, "ISteamClient_GetISteamApps");
	TRY_IAT_HOOK("SteamAPI_ISteamApps_BIsSubscribedApp", Hooked_BIsSubscribedApp_flat,
				 Orig_BIsSubscribedApp_flat, "ISteamApps_BIsSubscribedApp");
	TRY_IAT_HOOK("SteamAPI_Init", Hooked_SteamAPI_Init, Orig_SteamAPI_Init,
				 "SteamAPI_Init");
	TRY_IAT_HOOK("SteamAPI_InitFlat", Hooked_SteamAPI_InitFlat,
				 Orig_SteamAPI_InitFlat, "SteamAPI_InitFlat");
	TRY_IAT_HOOK("SteamInternal_SteamAPI_Init", Hooked_SteamInternal_SteamAPI_Init,
				 Orig_SteamInternal_Init, "SteamInternal_SteamAPI_Init");
	if (!isReloaded) {
		TRY_IAT_HOOK("SteamAPI_IsSteamRunning", Hooked_IsSteamRunning,
					 Orig_IsSteamRunning, "SteamAPI_IsSteamRunning");
	}
	TRY_IAT_HOOK("SteamAPI_GetSteamInstallPath", Hooked_GetSteamInstallPath,
				 Orig_GetSteamInstallPath, "SteamAPI_GetSteamInstallPath");
	TRY_IAT_HOOK("SteamInternal_FindOrCreateUserInterface",
				 Hooked_SteamInternal_FindOrCreateUserInterface,
				 Orig_FindOrCreateUserInterface,
				 "SteamInternal_FindOrCreateUserInterface");
	TRY_IAT_HOOK("SteamAPI_GetHSteamUser", Hooked_SteamAPI_GetHSteamUser,
				 Orig_GetHSteamUser, "SteamAPI_GetHSteamUser");
	TRY_IAT_HOOK("SteamInternal_CreateInterface", Hooked_SteamInternal_CreateInterface,
				 Orig_SteamInternal_CreateInterface, "SteamInternal_CreateInterface");

#undef TRY_IAT_HOOK

#define DO_IAT_HOOK_STEAMUSER(ver)                                               \
	do {                                                                         \
		auto p = (void *)GetProcAddress(hSteamApi, "SteamAPI_SteamUser_v" #ver); \
		if (p) {                                                                 \
			int _n = IATHookByAddress(p, (void *)&Hooked_SteamUser##ver,         \
									  (void **)&Orig_SteamUser##ver);            \
			RegisterIATHook("SteamAPI_SteamUser_v" #ver,                         \
							(void *)&Hooked_SteamUser##ver, p);                  \
			LOG("[DSE-DLL] Hooked SteamAPI_SteamUser_v" #ver " (%d)\n", _n);     \
		}                                                                        \
	} while (0)

	DO_IAT_HOOK_STEAMUSER(015);
	DO_IAT_HOOK_STEAMUSER(016);
	DO_IAT_HOOK_STEAMUSER(017);
	DO_IAT_HOOK_STEAMUSER(018);
	DO_IAT_HOOK_STEAMUSER(019);
	DO_IAT_HOOK_STEAMUSER(020);
	DO_IAT_HOOK_STEAMUSER(021);
	DO_IAT_HOOK_STEAMUSER(022);
	DO_IAT_HOOK_STEAMUSER(023);
	DO_IAT_HOOK_STEAMUSER(024);
	DO_IAT_HOOK_STEAMUSER(025);

#define DO_IAT_HOOK_STEAMFRIENDS(ver)                                           \
	do {                                                                        \
		auto p = (void *)GetProcAddress(hSteamApi,                              \
										"SteamAPI_SteamFriends_v" #ver);        \
		if (p) {                                                                \
			int _n = IATHookByAddress(p, (void *)&Hooked_SteamFriends##ver,     \
									  (void **)&Orig_SteamFriends##ver);        \
			RegisterIATHook("SteamAPI_SteamFriends_v" #ver,                     \
							(void *)&Hooked_SteamFriends##ver, p);              \
			LOG("[DSE-DLL] Hooked SteamAPI_SteamFriends_v" #ver " (%d)\n", _n); \
		}                                                                       \
	} while (0)

	DO_IAT_HOOK_STEAMFRIENDS(010);
	DO_IAT_HOOK_STEAMFRIENDS(011);
	DO_IAT_HOOK_STEAMFRIENDS(012);
	DO_IAT_HOOK_STEAMFRIENDS(013);
	DO_IAT_HOOK_STEAMFRIENDS(014);
	DO_IAT_HOOK_STEAMFRIENDS(015);
	DO_IAT_HOOK_STEAMFRIENDS(016);
	DO_IAT_HOOK_STEAMFRIENDS(017);
	DO_IAT_HOOK_STEAMFRIENDS(018);
	DO_IAT_HOOK_STEAMFRIENDS(019);
	DO_IAT_HOOK_STEAMFRIENDS(020);

#define DO_IAT_HOOK_STEAMAPPS(ver)                                           \
	do {                                                                     \
		auto p = (void *)GetProcAddress(hSteamApi,                           \
										"SteamAPI_SteamApps_v" #ver);        \
		if (p) {                                                             \
			int _n = IATHookByAddress(p, (void *)&Hooked_SteamApps##ver,     \
									  (void **)&Orig_SteamApps##ver);        \
			RegisterIATHook("SteamAPI_SteamApps_v" #ver,                     \
							(void *)&Hooked_SteamApps##ver, p);              \
			LOG("[DSE-DLL] Hooked SteamAPI_SteamApps_v" #ver " (%d)\n", _n); \
		}                                                                    \
	} while (0)

	DO_IAT_HOOK_STEAMAPPS(001);
	DO_IAT_HOOK_STEAMAPPS(002);
	DO_IAT_HOOK_STEAMAPPS(003);
	DO_IAT_HOOK_STEAMAPPS(004);
	DO_IAT_HOOK_STEAMAPPS(005);
	DO_IAT_HOOK_STEAMAPPS(006);
	DO_IAT_HOOK_STEAMAPPS(007);
	DO_IAT_HOOK_STEAMAPPS(008);
	DO_IAT_HOOK_STEAMAPPS(009);

#define DO_IAT_HOOK_STEAMCLIENT(ver)                                           \
	do {                                                                       \
		auto p = (void *)GetProcAddress(hSteamApi,                             \
										"SteamAPI_SteamClient_v" #ver);        \
		if (p) {                                                               \
			int _n = IATHookByAddress(p, (void *)&Hooked_SteamClient##ver,     \
									  (void **)&Orig_SteamClient##ver);        \
			RegisterIATHook("SteamAPI_SteamClient_v" #ver,                     \
							(void *)&Hooked_SteamClient##ver, p);              \
			LOG("[DSE-DLL] Hooked SteamAPI_SteamClient_v" #ver " (%d)\n", _n); \
		}                                                                      \
	} while (0)

	DO_IAT_HOOK_STEAMCLIENT(010);
	DO_IAT_HOOK_STEAMCLIENT(011);
	DO_IAT_HOOK_STEAMCLIENT(012);
	DO_IAT_HOOK_STEAMCLIENT(013);
	DO_IAT_HOOK_STEAMCLIENT(014);
	DO_IAT_HOOK_STEAMCLIENT(015);
	DO_IAT_HOOK_STEAMCLIENT(016);
	DO_IAT_HOOK_STEAMCLIENT(017);
	DO_IAT_HOOK_STEAMCLIENT(018);
	DO_IAT_HOOK_STEAMCLIENT(019);
	DO_IAT_HOOK_STEAMCLIENT(020);
	DO_IAT_HOOK_STEAMCLIENT(021);

	do {
		auto p = (void *)GetProcAddress(hSteamApi, "SteamClient");
		if (p) {
			int _n = IATHookByAddress(p, (void *)&Hooked_SteamClient021,
									  (void **)&Orig_SteamClient021);
			RegisterIATHook("SteamClient", (void *)&Hooked_SteamClient021, p);
			LOG("[DSE-DLL] Hooked SteamClient (flat API) (%d)\n", _n);
		}
	} while (0);

	LOG("[DSE-DLL] Steam API hooks installed.\n");
}

// LoadLibrary hooks
typedef HMODULE(WINAPI *pfn_LoadLibraryW)(LPCWSTR);
typedef HMODULE(WINAPI *pfn_LoadLibraryExW)(LPCWSTR, HANDLE, DWORD);
static pfn_LoadLibraryW Orig_LoadLibraryW = nullptr;
static pfn_LoadLibraryExW Orig_LoadLibraryExW = nullptr;

static bool IsSteamApiDll(LPCWSTR lpFileName) {
	if (!lpFileName)
		return false;
	const WCHAR *fname = lpFileName;
	const WCHAR *sep = wcsrchr(lpFileName, L'\\');
	if (!sep)
		sep = wcsrchr(lpFileName, L'/');
	if (sep)
		fname = sep + 1;
	return (_wcsicmp(fname, L"steam_api64.dll") == 0 ||
			_wcsicmp(fname, L"steam_api.dll") == 0);
}

HMODULE WINAPI Hooked_LoadLibraryW(LPCWSTR lpLibFileName) {
	HMODULE hMod = Orig_LoadLibraryW(lpLibFileName);
	if (hMod && !g_steamHooked && IsSteamApiDll(lpLibFileName)) {
		LOG("[DSE-DLL] LoadLibraryW caught: %ls\n", lpLibFileName);
		g_hSteamApiModule = hMod;
		HookSteamAPI(hMod);
	}
	return hMod;
}

HMODULE WINAPI Hooked_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile,
									 DWORD dwFlags) {
	HMODULE hMod = Orig_LoadLibraryExW(lpLibFileName, hFile, dwFlags);
	const DWORD kDataFlags = LOAD_LIBRARY_AS_DATAFILE |
							 LOAD_LIBRARY_AS_IMAGE_RESOURCE |
							 LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE;
	if (hMod && !g_steamHooked && IsSteamApiDll(lpLibFileName) &&
		!(dwFlags & kDataFlags)) {
		LOG("[DSE-DLL] LoadLibraryExW caught: %ls\n", lpLibFileName);
		g_hSteamApiModule = hMod;
		HookSteamAPI(hMod);
	}
	return hMod;
}

// Entry point
static void InitSteamHooks() {
	{
		void *pGPA = (void *)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetProcAddress");
		if (pGPA) {
			int n = IATHookByAddress(pGPA, (void *)&Hooked_GetProcAddress, (void **)&Orig_GetProcAddress);
			LOG("[DSE-DLL] hooked GetProcAddress (%d entries)\n", n);
		}
	}

	HMODULE hExisting = GetModuleHandleW(L"steam_api64.dll");
	if (!hExisting)
		hExisting = GetModuleHandleW(L"steam_api.dll");
	if (hExisting) {
		LOG("[DSE-DLL] steam_api already loaded - hooking now\n");
		g_hSteamApiModule = hExisting;
		HookSteamAPI(hExisting);
		return;
	}

	{
		void *pLLW = (void *)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
		if (pLLW) {
			int n = IATHookByAddress(pLLW, (void *)&Hooked_LoadLibraryW, (void **)&Orig_LoadLibraryW);
			LOG("[DSE-DLL] IAT-hooked LoadLibraryW (%d entries)\n", n);
		}
		void *pLLExW = (void *)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryExW");
		if (pLLExW) {
			int n = IATHookByAddress(pLLExW, (void *)&Hooked_LoadLibraryExW, (void **)&Orig_LoadLibraryExW);
			LOG("[DSE-DLL] IAT-hooked LoadLibraryExW (%d entries)\n", n);
		}
	}
	LOG("[DSE-DLL] LoadLibrary hooks set - waiting for steam_api64.dll\n");
}
