#define WIN32_LEAN_AND_MEAN

#include <vector>
#include "config.h"
#include "log.h"
#include "hooks.h"
#include "minhook/include/MinHook.h"
#include <cstdint>
#include <shlwapi.h>
#include <utility>
#include <windows.h>

static uint64_t g_fakeSteamID = 76561197960287930ULL; // default SteamID
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
		_snprintf_s(envBuf, ARRAYSIZE(envBuf), _TRUNCATE, "%u", appId);
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
// CSteamID is returned through a hidden return buffer for this game's MSVC
// x64 vtable calls: RCX = instance, RDX = hidden output buffer.
typedef uint64_t *(*pfn_GetSteamID_vtable)(void *self, uint64_t *pOut);
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
	for (const DLCInfo &dlc : g_unlockedDlcs)
		if (dlc.appId == appId)
			return true;
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

static void HookInterface_ISteamUser(void *pInterface, const char *pszVersion);
static void HookInterface_ISteamFriends(void *pInterface);

typedef void *(*pfn_ISteamClient_GetISteamUser_flat)(void *self, int32_t hSteamUser, int32_t hSteamPipe, const char *pchVersion);
static pfn_ISteamClient_GetISteamUser_flat Orig_ISteamClient_GetISteamUser_flat = nullptr;

static void *Hooked_ISteamClient_GetISteamUser_flat(void *self, int32_t hSteamUser, int32_t hSteamPipe, const char *pchVersion) {
	void *p = Orig_ISteamClient_GetISteamUser_flat
				  ? Orig_ISteamClient_GetISteamUser_flat(self, hSteamUser, hSteamPipe, pchVersion)
				  : nullptr;
	LOG("[DSE-DLL] SteamAPI_ISteamClient_GetISteamUser(%s, %d, %d) -> %p\n",
		pchVersion ? pchVersion : "(null)", hSteamUser, hSteamPipe, p);
	if (p)
		HookInterface_ISteamUser(p, pchVersion);
	return p;
}

typedef void *(*pfn_ISteamClient_GetISteamFriends_flat)(void *self, int32_t hSteamUser, int32_t hSteamPipe, const char *pchVersion);
static pfn_ISteamClient_GetISteamFriends_flat Orig_ISteamClient_GetISteamFriends_flat = nullptr;

static void *Hooked_ISteamClient_GetISteamFriends_flat(void *self, int32_t hSteamUser, int32_t hSteamPipe, const char *pchVersion) {
	void *p = Orig_ISteamClient_GetISteamFriends_flat
				  ? Orig_ISteamClient_GetISteamFriends_flat(self, hSteamUser, hSteamPipe, pchVersion)
				  : nullptr;
	LOG("[DSE-DLL] SteamAPI_ISteamClient_GetISteamFriends(%s, %d, %d) -> %p\n",
		pchVersion ? pchVersion : "(null)", hSteamUser, hSteamPipe, p);
	if (p)
		HookInterface_ISteamFriends(p);
	return p;
}

// VTable hooks
static uint64_t *Hooked_GetSteamID_vtable(void *self, uint64_t *pOut) {
	uint64_t localBuf = 0;
	uint64_t *out = pOut ? pOut : &localBuf;
	uint64_t orig = 0;

	pfn_GetSteamID_vtable origFn =
		(pfn_GetSteamID_vtable)GetGenericOriginalSlotForDetour(
			self, (void *)&Hooked_GetSteamID_vtable, (void *)Orig_GetSteamID_vtable);
	if (origFn) {
		origFn(self, out);
		if (!TryReadValue(out, &orig)) {
			orig = 0;
		}
	}

	uint64_t ret = SelectSteamID(orig);
	if (!TryWriteValue(out, ret)) {
		LOG("[DSE-DLL] ISteamUser::GetSteamID() could not write pOut=%p\n", out);
	} else {
		LOG("[DSE-DLL] ISteamUser::GetSteamID() orig=%llu -> %llu\n",
			(unsigned long long)orig, (unsigned long long)ret);
	}

	return out;
}

typedef void *(*pfn_GetAppOwner_vtable)(void *self, uint64_t *pOut);
static pfn_GetAppOwner_vtable Orig_GetAppOwner_vtable = nullptr;

static void *Hooked_GetAppOwner_vtable(void *self, uint64_t *pOut) {
	uint64_t localBuf = 0;
	uint64_t orig = 0;
	bool usedHiddenBuf = false;

	pfn_GetAppOwner_vtable origFn =
		(pfn_GetAppOwner_vtable)GetGenericOriginalSlotForDetour(
			self, (void *)&Hooked_GetAppOwner_vtable, (void *)Orig_GetAppOwner_vtable);
	if (origFn) {
		void *raw = origFn(self, &localBuf);
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
	pfn_GetPersonaState_vtable origFn =
		(pfn_GetPersonaState_vtable)GetGenericOriginalSlotForDetour(
			self, (void *)&Hooked_GetPersonaState_vtable, (void *)Orig_GetPersonaState_vtable);
	int orig = origFn ? origFn(self) : 0;
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

static void **g_pISteamClientVTable = nullptr;

template<int Slot>
struct ClientSlotHookT {
	using fn_t = void *(*)(void *self, int32_t hSteamUser, int32_t hSteamPipe, const char *pchVersion);
	static fn_t Orig;
	static void *Hooked(void *self, int32_t hSteamUser, int32_t hSteamPipe, const char *pchVersion) {
		fn_t orig = (fn_t)GetClientOriginalSlot(self, Slot, (void *)Orig);
		void *p = orig ? orig(self, hSteamUser, hSteamPipe, pchVersion) : nullptr;
		if (p && pchVersion) {
			LOG("[DSE-DLL] ISteamClient::Slot%d(%s) -> %p\n", Slot, pchVersion, p);
			HookSteamInterfaceByVersion(p, pchVersion);
		}
		return p;
	}
};
template<int Slot> typename ClientSlotHookT<Slot>::fn_t ClientSlotHookT<Slot>::Orig = nullptr;

typedef void (*pfn_ClientSlot4)(void *self, int32_t hSteamPipe, int32_t hUser);
static pfn_ClientSlot4 Orig_ClientSlot4 = nullptr;
static void Hooked_ClientSlot4(void *self, int32_t hSteamPipe, int32_t hUser) {
	LOG("[DSE-DLL] ISteamClient::Slot4 (ReleaseUser) %d %d -> forwarded\n", hSteamPipe, hUser);
	pfn_ClientSlot4 orig = (pfn_ClientSlot4)GetClientOriginalSlot(self, 4, (void *)Orig_ClientSlot4);
	if (orig)
		orig(self, hSteamPipe, hUser);
	LOG("[DSE-DLL] ISteamClient::Slot4 (ReleaseUser) -> forwarded SUCCESS\n");
}

static void (*Orig_SetCallbackCheck)(void *self, void *func) = nullptr;
static void Hooked_SetCallbackCheck(void *self, void *func) {
	LOG("[DSE-DLL] ISteamClient::Set_SteamAPI_CCheckCallbackRegisteredInProcess -> forwarded\n");
	auto orig = (decltype(Orig_SetCallbackCheck))GetClientCallbackOriginal(
		self, (void *)Orig_SetCallbackCheck);
	if (orig)
		orig(self, func);
}

typedef void *(*pfn_ClientSlot9)(void *self, int32_t hSteamPipe, const char *pchVersion);
static pfn_ClientSlot9 Orig_ClientSlot9 = nullptr;
static void *Hooked_ClientSlot9(void *self, int32_t hSteamPipe, const char *pchVersion) {
	pfn_ClientSlot9 orig = (pfn_ClientSlot9)GetClientOriginalSlot(self, 9, (void *)Orig_ClientSlot9);
	void *p = orig ? orig(self, hSteamPipe, pchVersion) : nullptr;
	LOG("[DSE-DLL] ISteamClient::Slot9 (utils) -> %p\n", p);
	return p;
}
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
	auto orig = (decltype(Orig_ClientSlot12))GetClientOriginalSlot(self, 12, (void *)Orig_ClientSlot12);
	void *p = orig ? orig(self, hSteamUser, hSteamPipe, pchVersion) : nullptr;
	LOG("[DSE-DLL] ISteamClient::Slot12 (GetISteamGenericInterface) %s -> %p\n", pchVersion, p);
	if (p && pchVersion)
		HookSteamInterfaceByVersion(p, pchVersion);
	return p;
}
struct ClientSlotHook {
	int slot;
	LPVOID hookFn;
	LPVOID *origFn;
};

static const ClientSlotHook kClientSlotHooks[] = {
	{4,  (LPVOID)&Hooked_ClientSlot4,              (LPVOID*)&Orig_ClientSlot4},
	{5,  (LPVOID)&ClientSlotHookT<5>::Hooked,      (LPVOID*)&ClientSlotHookT<5>::Orig},
	{8,  (LPVOID)&ClientSlotHookT<8>::Hooked,      (LPVOID*)&ClientSlotHookT<8>::Orig},
	{9,  (LPVOID)&Hooked_ClientSlot9,              (LPVOID*)&Orig_ClientSlot9},
	{10, (LPVOID)&ClientSlotHookT<10>::Hooked,     (LPVOID*)&ClientSlotHookT<10>::Orig},
	{11, (LPVOID)&ClientSlotHookT<11>::Hooked,     (LPVOID*)&ClientSlotHookT<11>::Orig},
	{12, (LPVOID)&Hooked_ClientSlot12,             (LPVOID*)&Orig_ClientSlot12},
	{13, (LPVOID)&ClientSlotHookT<13>::Hooked,     (LPVOID*)&ClientSlotHookT<13>::Orig},
	{14, (LPVOID)&ClientSlotHookT<14>::Hooked,     (LPVOID*)&ClientSlotHookT<14>::Orig},
	{15, (LPVOID)&ClientSlotHookT<15>::Hooked,     (LPVOID*)&ClientSlotHookT<15>::Orig},
	{16, (LPVOID)&ClientSlotHookT<16>::Hooked,     (LPVOID*)&ClientSlotHookT<16>::Orig},
};

typedef uint32_t (*pfn_GetEarliestPurchaseUnixTime_vtable)(void *self, uint32_t appID);
static pfn_GetEarliestPurchaseUnixTime_vtable Orig_GetEarliestPurchaseUnixTime_vtable = nullptr;

static uint32_t Hooked_GetEarliestPurchaseUnixTime_vtable(void *self, uint32_t appID) {
	(void)self;
	if (CheckAppSubscribed(appID)) {
		LOG("[DSE-DLL] ISteamApps::GetEarliestPurchaseUnixTime(%u) -> spoofed\n", appID);
		return 1700000000;
	}
	pfn_GetEarliestPurchaseUnixTime_vtable origFn =
		(pfn_GetEarliestPurchaseUnixTime_vtable)GetGenericOriginalSlotForDetour(
			self, (void *)&Hooked_GetEarliestPurchaseUnixTime_vtable,
			(void *)Orig_GetEarliestPurchaseUnixTime_vtable);
	uint32_t orig = origFn ? origFn(self, appID) : 0;
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
	for (const DLCInfo &dlc : g_unlockedDlcs) {
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
		const DLCInfo &dlc = g_unlockedDlcs[iDLC];
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

static void SwapVTable(void *pInterface, void ***pFakeVTableOut, void ***pRealVTableOut, void **staticBuffer, size_t numSlots = 100) {
	void **vtable = *(void ***)pInterface;
	if (*pFakeVTableOut && vtable == *pFakeVTableOut)
		return;

	*pRealVTableOut = vtable;

	void **fakeVTable = &staticBuffer[2];

	// Copy RTTI metadata and the VTable itself
	TryReadValue(vtable - 2, fakeVTable - 2); // Sometimes useful
	TryReadValue(vtable - 1, fakeVTable - 1); // RTTI CompleteObjectLocator

	for (size_t i = 0; i < numSlots; i++) {
		if (!TryReadValue(vtable + i, fakeVTable + i)) {
			break;
		}
	}

	DWORD oldProtect;
	VirtualProtect(pInterface, sizeof(void *), PAGE_READWRITE, &oldProtect);
	*(void ***)pInterface = fakeVTable;
	VirtualProtect(pInterface, sizeof(void *), oldProtect, &oldProtect);

	*pFakeVTableOut = fakeVTable;
	LOG("[DSE-DLL] VTable swapped object at %p\n", pInterface);
}

static void TryHookVTableSlot_Swap(void **fakeVTable, void **realVTable, int slot, LPVOID detour, LPVOID *orig, const char *name) {
	if (!fakeVTable || !realVTable || slot < 0 || !realVTable[slot])
		return;

	if (orig)
		*orig = realVTable[slot];
	fakeVTable[slot] = detour;
	LOG("[DSE-DLL]   Swapped %s slot [%d] @ %p -> %p\n", name, slot, realVTable[slot], detour);
}

static void **g_pFakeSteamUserVTable = nullptr;
static void *g_FakeSteamUserVTableBuffer[102];

static void HookInterface_ISteamUser(void *pInterface, const char *pszVersion) {
	if (!pInterface)
		return;

	bool freshSwap = false;
	GenericVTableSwap *swap = BeginGenericVTableSwapLocked(pInterface, 100, &freshSwap);
	if (!swap)
		return;
	if (!freshSwap)
		return;

	void **realVTable = swap->realVTable;
	void **fakeVTable = swap->fakeVTable;
	g_pFakeSteamUserVTable = fakeVTable;
	if (!g_pISteamUserVTable)
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

	TryHookVTableSlot_Swap(fakeVTable, realVTable, loggedOnSlot, (LPVOID)&Hooked_BLoggedOn_vtable,
						   (LPVOID *)&Orig_BLoggedOn_vtable, "ISteamUser::BLoggedOn");
	TryHookVTableSlot_Swap(fakeVTable, realVTable, getIDSlot, (LPVOID)&Hooked_GetSteamID_vtable,
						   (LPVOID *)&Orig_GetSteamID_vtable, "ISteamUser::GetSteamID");
	if (userHasLicenseSlot >= 0)
		TryHookVTableSlot_Swap(fakeVTable, realVTable, userHasLicenseSlot, (LPVOID)&Hooked_UserHasLicenseForApp_flat,
							   nullptr, "ISteamUser::UserHasLicenseForApp");
	PublishGenericVTableSwapLocked(swap);
}

static void **g_pFakeSteamFriendsVTable = nullptr;
static void *g_FakeSteamFriendsVTableBuffer[102];

static void HookInterface_ISteamFriends(void *pInterface) {
	if (!pInterface)
		return;

	bool freshSwap = false;
	GenericVTableSwap *swap = BeginGenericVTableSwapLocked(pInterface, 100, &freshSwap);
	if (!swap)
		return;
	if (!freshSwap)
		return;

	void **realVTable = swap->realVTable;
	void **fakeVTable = swap->fakeVTable;
	g_pFakeSteamFriendsVTable = fakeVTable;
	if (!g_pISteamFriendsVTable)
		g_pISteamFriendsVTable = realVTable;
	LOG("[DSE-DLL] Intercepted ISteamFriends vtable at %p\n", realVTable);

	// GetPersonaName is slot 0, GetPersonaState is slot 1 (all SteamFriends
	// versions 010-021). Slot 2 is GetFriendCount.
	TryHookVTableSlot_Swap(fakeVTable, realVTable, 1, (LPVOID)&Hooked_GetPersonaState_vtable,
						   (LPVOID *)&Orig_GetPersonaState_vtable, "ISteamFriends::GetPersonaState");
	PublishGenericVTableSwapLocked(swap);
}

static void **g_pISteamAppTicketVTable = nullptr;
static void **g_pFakeSteamAppTicketVTable = nullptr;
static void *g_FakeSteamAppTicketVTableBuffer[102];

static void HookInterface_ISteamAppTicket(void *pInterface) {
	if (!pInterface)
		return;

	bool freshSwap = false;
	GenericVTableSwap *swap = BeginGenericVTableSwapLocked(pInterface, 100, &freshSwap);
	if (!swap)
		return;
	if (!freshSwap)
		return;

	void **realVTable = swap->realVTable;
	void **fakeVTable = swap->fakeVTable;
	g_pFakeSteamAppTicketVTable = fakeVTable;
	if (!g_pISteamAppTicketVTable)
		g_pISteamAppTicketVTable = realVTable;
	LOG("[DSE-DLL] Intercepted ISteamAppTicket vtable at %p\n", realVTable);
	TryHookVTableSlot_Swap(fakeVTable, realVTable, 0, (LPVOID)&Hooked_GetAppOwnershipTicketData_vtable,
						   (LPVOID *)&Orig_GetAppOwnershipTicketData_vtable, "ISteamAppTicket::GetAppOwnershipTicketData");
	PublishGenericVTableSwapLocked(swap);
}

static void **g_pISteamAppsVTable = nullptr;
static int g_steamAppsVersion = 0;
static void **g_pFakeSteamAppsVTable = nullptr;
static void *g_FakeSteamAppsVTableBuffer[102];

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

	bool freshSwap = false;
	GenericVTableSwap *swap = BeginGenericVTableSwapLocked(pInterface, 100, &freshSwap);
	if (!swap)
		return;
	if (!freshSwap)
		return;

	void **realVTable = swap->realVTable;
	void **fakeVTable = swap->fakeVTable;
	g_pFakeSteamAppsVTable = fakeVTable;
	int ver = ParseSteamAppsVersion(pszVersion);
	if (!g_pISteamAppsVTable) {
		g_pISteamAppsVTable = realVTable;
		LOG("[DSE-DLL] Intercepted ISteamApps vtable at %p (ver=%d)\n", realVTable, ver);
	}
	if (ver > g_steamAppsVersion)
		g_steamAppsVersion = ver;

	auto HookAppSlot = [&](int slot, LPVOID detour, LPVOID *orig, const char *name) {
		TryHookVTableSlot_Swap(fakeVTable, realVTable, slot, detour, orig, name);
	};

	if (ver >= 2)
		HookAppSlot(0, (LPVOID)&Hooked_BIsSubscribed_vtable,
					(LPVOID *)&Orig_BIsSubscribed_vtable,
					"ISteamApps::BIsSubscribed");

	if (ver >= 2)
		HookAppSlot(6, (LPVOID)&Hooked_BIsSubscribedApp_vtable,
					(LPVOID *)&Orig_BIsSubscribedApp_vtable,
					"ISteamApps::BIsSubscribedApp");

	if (ver >= 2)
		HookAppSlot(7, (LPVOID)&Hooked_BIsDlcInstalled_vtable,
					(LPVOID *)&Orig_BIsDlcInstalled_vtable,
					"ISteamApps::BIsDlcInstalled");

	if (ver >= 3) {
		HookAppSlot(8, (LPVOID)&Hooked_GetEarliestPurchaseUnixTime_vtable,
					(LPVOID *)&Orig_GetEarliestPurchaseUnixTime_vtable,
					"ISteamApps::GetEarliestPurchaseUnixTime");
	}

	if (ver >= 4) {
		HookAppSlot(10, (LPVOID)&Hooked_GetDLCCount_vtable,
					(LPVOID *)&Orig_GetDLCCount_vtable,
					"ISteamApps::GetDLCCount");

		HookAppSlot(11, (LPVOID)&Hooked_BGetDLCDataByIndex_vtable,
					(LPVOID *)&Orig_BGetDLCDataByIndex_vtable,
					"ISteamApps::BGetDLCDataByIndex");
	}

	if (ver >= 6) {
		HookAppSlot(19, (LPVOID)&Hooked_BIsAppInstalled_vtable,
					(LPVOID *)&Orig_BIsAppInstalled_vtable,
					"ISteamApps::BIsAppInstalled");
	}

	if (ver >= 8) {
		HookAppSlot(20, (LPVOID)&Hooked_GetAppOwner_vtable,
					(LPVOID *)&Orig_GetAppOwner_vtable,
					"ISteamApps::GetAppOwner");
	}
	PublishGenericVTableSwapLocked(swap);
}

static void HookInterface_ISteamClient(void *pInterface, const char *pszVersion) {
	if (!pInterface)
		return;
	void **vtable = nullptr;
	if (!TryReadValue(reinterpret_cast<void ***>(pInterface), &vtable)) {
		return;
	}
	LOG("[DSE-DLL] Intercepted ISteamClient vtable at %p (%s)\n",
		vtable, pszVersion ? pszVersion : "unknown");

	int ver = 0;
	if (pszVersion && strncmp(pszVersion, "SteamClient0", 12) == 0) {
		ver = atoi(pszVersion + 12);
	}

	static const struct { int ver, slot; } kCallbackSlots[] = {
		{16, 34}, {17, 33}, {18, 34}, {19, 34}, {20, 34}, {21, 32}, {22, 31},
	};
	int callbackSlot = -1;
	for (const auto &cs : kCallbackSlots) {
		if (cs.ver == ver) { callbackSlot = cs.slot; break; }
	}

	bool freshSwap = false;
	ClientVTableSwap *swap = BeginClientVTableSwapLocked(pInterface, kMaxClientVTableSlots, &freshSwap);
	if (swap && !freshSwap)
		return;
	if (!swap || !swap->realVTable || !swap->fakeVTable)
		return;
	void **realVTable = swap->realVTable;
	void **fakeVTable = swap->fakeVTable;
	swap->callbackSlot = callbackSlot;
	if (!g_pISteamClientVTable)
		g_pISteamClientVTable = realVTable;

	for (const auto &h : kClientSlotHooks) {
		char label[64];
		_snprintf_s(label, sizeof(label), _TRUNCATE, "ISteamClient::Slot%d", h.slot);
		TryHookVTableSlot_Swap(fakeVTable, realVTable, h.slot, h.hookFn, h.origFn, label);
	}

	if (callbackSlot != -1) {
		TryHookVTableSlot_Swap(fakeVTable, realVTable, callbackSlot, (LPVOID)&Hooked_SetCallbackCheck, (LPVOID *)&Orig_SetCallbackCheck, "ISteamClient::Set_SteamAPI_CCheckCallbackRegisteredInProcess");
	}
	PublishClientVTableSwapLocked(swap);
}

static void *
Hooked_SteamInternal_FindOrCreateUserInterface(int32_t hSteamUser,
											   const char *pszVersion) {
	void *p = Orig_FindOrCreateUserInterface
				  ? Orig_FindOrCreateUserInterface(hSteamUser, pszVersion)
				  : nullptr;
	HookSteamInterfaceByVersion(p, pszVersion);
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

// Probe FindOrCreateUserInterface with known ISteamUser versions until one
// resolves, then install the hooks. FindOrCreateUserInterface only succeeds
// for the version the loaded steamclient was built for, so extra entries are
// harmless.
static const char *const kSteamUserProbeVersions[] = {
	"SteamUser025", "SteamUser024", "SteamUser023", "SteamUser022",
	"SteamUser021", "SteamUser020", "SteamUser019", "SteamUser018",
	"SteamUser017", "SteamUser016", "SteamUser015", nullptr};

static void ProbeAndHookSteamUser(int32_t hUser) {
	if (!Orig_FindOrCreateUserInterface)
		return;
	for (int i = 0; kSteamUserProbeVersions[i]; i++) {
		void *pUser = Orig_FindOrCreateUserInterface(hUser, kSteamUserProbeVersions[i]);
		if (pUser) {
			LOG("[DSE-DLL] Force-hooking ISteamUser via %s @ %p\n",
				kSteamUserProbeVersions[i], pUser);
			HookInterface_ISteamUser(pUser, kSteamUserProbeVersions[i]);
			return;
		}
	}
}

// SteamAPI_GetHSteamUser
// Intercept so we can
// force-install the ISteamUser vtable hook the moment the game resolves its
// user handle before it ever calls GetSteamID().
static int32_t Hooked_SteamAPI_GetHSteamUser() {
	int32_t hUser = Orig_GetHSteamUser ? Orig_GetHSteamUser() : 0;
	LOG("[DSE-DLL] SteamAPI_GetHSteamUser() = %d\n", hUser);
	if (hUser && !g_pISteamUserVTable)
		ProbeAndHookSteamUser(hUser);
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

// Dynamic versioned accessor hooks
// Versioned flat accessors: SteamAPI_<export>vNNN() each return an interface
// pointer. One thunk per (family, version) is generated from the family's suffix
// list below; it calls the saved original accessor to get the pointer, then hands
// it to Hook tagged with <version>NNN (the slot resolvers need the exact
// version). Adding a version is one line in kSuffixes.
struct FamSteamUser {
	static constexpr const char *kExport = "SteamAPI_SteamUser_v";
	static constexpr const char *kVersion = "SteamUser";
	static constexpr const char *kSuffixes[] = {
		"015", "016", "017", "018", "019", "020", "021", "022", "023", "024", "025"};
	static constexpr size_t kCount = sizeof(kSuffixes) / sizeof(*kSuffixes);
	static inline void *origs[kCount]{};
	static void Hook(void *p, const char *v) { HookInterface_ISteamUser(p, v); }
};

struct FamSteamFriends {
	static constexpr const char *kExport = "SteamAPI_SteamFriends_v";
	static constexpr const char *kVersion = "SteamFriends";
	static constexpr const char *kSuffixes[] = {
		"010", "011", "012", "013", "014", "015", "016", "017", "018", "019", "020"};
	static constexpr size_t kCount = sizeof(kSuffixes) / sizeof(*kSuffixes);
	static inline void *origs[kCount]{};
	static void Hook(void *p, const char *) { HookInterface_ISteamFriends(p); }
};

struct FamSteamApps {
	static constexpr const char *kExport = "SteamAPI_SteamApps_v";
	static constexpr const char *kVersion = "STEAMAPPS_INTERFACE_VERSION";
	static constexpr const char *kSuffixes[] = {
		"001", "002", "003", "004", "005", "006", "007", "008", "009"};
	static constexpr size_t kCount = sizeof(kSuffixes) / sizeof(*kSuffixes);
	static inline void *origs[kCount]{};
	static void Hook(void *p, const char *v) { HookInterface_ISteamApps(p, v); }
};

struct FamSteamClient {
	static constexpr const char *kExport = "SteamAPI_SteamClient_v";
	static constexpr const char *kVersion = "SteamClient";
	static constexpr const char *kSuffixes[] = {
		"010", "011", "012", "013", "014", "015", "016", "017", "018", "019", "020", "021"};
	static constexpr size_t kCount = sizeof(kSuffixes) / sizeof(*kSuffixes);
	static inline void *origs[kCount]{};
	static void Hook(void *p, const char *v) { HookInterface_ISteamClient(p, v); }
};

template <class Fam, size_t I>
static void *VersionedThunk() {
	void *p = Fam::origs[I] ? reinterpret_cast<void *(*)()>(Fam::origs[I])() : nullptr;
	char ver[64];
	_snprintf_s(ver, sizeof(ver), _TRUNCATE, "%s%s", Fam::kVersion, Fam::kSuffixes[I]);
	Fam::Hook(p, ver);
	return p;
}

// The unversioned SteamClient() export returns the same ISteamClient; hook it
// with the newest layout, same as the old flat hook did.
static void *Orig_SteamClientFlat = nullptr;
static void *Hooked_SteamClientFlat() {
	void *p = Orig_SteamClientFlat ? reinterpret_cast<void *(*)()>(Orig_SteamClientFlat)() : nullptr;
	HookInterface_ISteamClient(p, "SteamClient021");
	return p;
}

static void PreHookSingletons() {
	HMODULE hSteamApi = GetModuleHandleW(L"steam_api64.dll");
	if (!hSteamApi)
		hSteamApi = GetModuleHandleW(L"steam_api.dll");
	if (!hSteamApi)
		return;

	// Retargeted export trampolines only catch calls through the EAT/IAT; steam_api's
	// own internal calls bypass them. Pre-hook every ISteamClient it can hand out so
	// vtable-based GetISteamUser/GetISteamApps/GetISteamFriends go through our
	// accessors, same as HookRealClientInterfaces does for the coldclient path.
	if (Orig_SteamInternal_CreateInterface) {
		static const char *const kClientVersions[] = {
			"SteamClient021", "SteamClient020", "SteamClient019", "SteamClient018",
			"SteamClient017", "SteamClient016", "SteamClient015", "SteamClient014",
			nullptr};
		for (int i = 0; kClientVersions[i]; i++) {
			void *client = Orig_SteamInternal_CreateInterface(kClientVersions[i]);
			if (client) {
				LOG("[DSE-DLL] Pre-hooking ISteamClient via %s @ %p (forward)\n",
					kClientVersions[i], client);
				HookInterface_ISteamClient(client, kClientVersions[i]);
			}
		}
	}

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
		ProbeAndHookSteamUser(hUser);
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

// Init hooks
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

// Resolve Steam path from registry.
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
	if (!g_config.coldloaderhooks) {
		WCHAR clientPath[MAX_PATH]{};
		lstrcpynW(clientPath, wPath, MAX_PATH);
		PathAppendW(clientPath, L"steamclient64.dll");
		SetEnvironmentVariableW(L"SteamClientDll64", clientPath);
		SetDllDirectoryW(wPath);
	} else {
		SetEnvironmentVariableW(L"SteamClientDll64", NULL);
	}
	LOG("[DSE-DLL] Set SteamPath env = %s (coldloaderhooks=%d)\n", g_steamPath, g_config.coldloaderhooks);
}

// Each steam_api export is a `jmp [rip+0]; <target>` trampoline: into
// steam_api64_o.dll with steamApiForward, or into its own code otherwise
// (HookSteamApiInPlace). Swapping the target hooks the export without patching
// code or freezing threads. Exports that are not trampolines are skipped.
static bool RetargetForwardedExport(LPVOID p, LPVOID hookFn, LPVOID *origFn) {
	static const BYTE kJmpRip[6] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
	BYTE *t = (BYTE *)p;
	if (memcmp(t, kJmpRip, sizeof(kJmpRip)) != 0)
		return false;
	DWORD oldProt;
	if (!VirtualProtect(t + 6, sizeof(void *), PAGE_EXECUTE_READWRITE, &oldProt))
		return false;
	memcpy(origFn, t + 6, sizeof(void *));
	memcpy(t + 6, &hookFn, sizeof(void *));
	VirtualProtect(t + 6, sizeof(void *), oldProt, &oldProt);
	FlushInstructionCache(GetCurrentProcess(), t, 14);
	return true;
}

template <class Fam, size_t... I>
static void InstallVersionedFamily(HMODULE h, std::index_sequence<I...>) {
	static LPVOID const thunks[] = {(LPVOID)&VersionedThunk<Fam, I>...};
	char name[128];
	for (size_t i = 0; i < Fam::kCount; i++) {
		_snprintf_s(name, sizeof(name), _TRUNCATE, "%s%s", Fam::kExport, Fam::kSuffixes[i]);
		auto p = (LPVOID)GetProcAddress(h, name);
		if (p && RetargetForwardedExport(p, thunks[i], &Fam::origs[i]))
			LOG("[DSE-DLL]   Hooked %s\n", name);
	}
}

template <class Fam>
static void HookVersionedFamily(HMODULE h) {
	InstallVersionedFamily<Fam>(h, std::make_index_sequence<Fam::kCount>{});
}

struct FlatApiHook {
	const char *exportName;
	LPVOID hookFn;
	LPVOID *origFn;
	bool skipIfReloaded;
};

static const FlatApiHook kFlatApiHooks[] = {
	{"SteamAPI_RestartAppIfNecessary", (LPVOID)&Hooked_SteamAPI_RestartAppIfNecessary, (LPVOID*)&Orig_RestartApp, true},
	{"SteamAPI_ISteamUser_GetSteamID", (LPVOID)&Hooked_GetSteamID, (LPVOID*)&Orig_GetSteamID, false},
	{"SteamAPI_ISteamUser_BLoggedOn", (LPVOID)&Hooked_BLoggedOn, (LPVOID*)&Orig_BLoggedOn, false},
	{"SteamAPI_ISteamUser_UserHasLicenseForApp", (LPVOID)&Hooked_UserHasLicenseForApp_flat, (LPVOID*)&Orig_UserHasLicenseForApp_flat, false},
	{"SteamAPI_ISteamFriends_GetPersonaState", (LPVOID)&Hooked_GetPersonaState, (LPVOID*)&Orig_GetPersonaState, false},
	{"SteamAPI_ISteamAppTicket_GetAppOwnershipTicketData", (LPVOID)&Hooked_GetAppOwnershipTicketData_flat, (LPVOID*)&Orig_GetAppOwnershipTicketData_flat, false},
	{"SteamAPI_ISteamClient_GetISteamGenericInterface", (LPVOID)&Hooked_ISteamClient_GetISteamGenericInterface_flat, (LPVOID*)&Orig_ISteamClient_GetISteamGenericInterface_flat, false},
	{"SteamAPI_ISteamClient_GetISteamApps", (LPVOID)&Hooked_ISteamClient_GetISteamApps_flat, (LPVOID*)&Orig_ISteamClient_GetISteamApps_flat, false},
	{"SteamAPI_ISteamClient_GetISteamUser", (LPVOID)&Hooked_ISteamClient_GetISteamUser_flat, (LPVOID*)&Orig_ISteamClient_GetISteamUser_flat, false},
	{"SteamAPI_ISteamClient_GetISteamFriends", (LPVOID)&Hooked_ISteamClient_GetISteamFriends_flat, (LPVOID*)&Orig_ISteamClient_GetISteamFriends_flat, false},
	{"SteamAPI_ISteamApps_BIsSubscribedApp", (LPVOID)&Hooked_BIsSubscribedApp_flat, (LPVOID*)&Orig_BIsSubscribedApp_flat, false},
	{"SteamAPI_Init", (LPVOID)&Hooked_SteamAPI_Init, (LPVOID*)&Orig_SteamAPI_Init, false},
	{"SteamAPI_InitFlat", (LPVOID)&Hooked_SteamAPI_InitFlat, (LPVOID*)&Orig_SteamAPI_InitFlat, false},
	{"SteamInternal_SteamAPI_Init", (LPVOID)&Hooked_SteamInternal_SteamAPI_Init, (LPVOID*)&Orig_SteamInternal_Init, false},
	{"SteamAPI_IsSteamRunning", (LPVOID)&Hooked_IsSteamRunning, (LPVOID*)&Orig_IsSteamRunning, true},
	{"SteamAPI_GetSteamInstallPath", (LPVOID)&Hooked_GetSteamInstallPath, (LPVOID*)&Orig_GetSteamInstallPath, false},
	{"SteamInternal_FindOrCreateUserInterface", (LPVOID)&Hooked_SteamInternal_FindOrCreateUserInterface, (LPVOID*)&Orig_FindOrCreateUserInterface, false},
	{"SteamAPI_GetHSteamUser", (LPVOID)&Hooked_SteamAPI_GetHSteamUser, (LPVOID*)&Orig_GetHSteamUser, false},
	{"SteamInternal_CreateInterface", (LPVOID)&Hooked_SteamInternal_CreateInterface, (LPVOID*)&Orig_SteamInternal_CreateInterface, false},
};

// Hook all steam_api exports.
static void HookSteamAPI(HMODULE hSteamApi) {
	if (g_config.coldloaderhooks) {
		LOG("[DSE-DLL] HookSteamAPI called but coldloaderhooks is enabled - skipping steam_api64 patching\n");
		return;
	}
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

	for (const auto &h : kFlatApiHooks) {
		if (h.skipIfReloaded && isReloaded)
			continue;
		auto p = (LPVOID)GetProcAddress(hSteamApi, h.exportName);
		if (p) {
			if (RetargetForwardedExport(p, h.hookFn, h.origFn))
				LOG("[DSE-DLL]   Hooked %s\n", h.exportName);
			else
				LOG("[DSE-DLL]   Failed to hook %s\n", h.exportName);
		} else
			LOG("[DSE-DLL]   %s export not found\n", h.exportName);
	}

	HookVersionedFamily<FamSteamUser>(hSteamApi);
	HookVersionedFamily<FamSteamFriends>(hSteamApi);
	HookVersionedFamily<FamSteamApps>(hSteamApi);
	HookVersionedFamily<FamSteamClient>(hSteamApi);

	auto pSteamClient = (LPVOID)GetProcAddress(hSteamApi, "SteamClient");
	if (pSteamClient && RetargetForwardedExport(pSteamClient, (LPVOID)&Hooked_SteamClientFlat, &Orig_SteamClientFlat))
		LOG("[DSE-DLL]   Hooked SteamClient (flat API)\n");

	LOG("[DSE-DLL] Steam API hooks installed.\n");
}

static void HookSteamApiInPlace(HMODULE hSteamApi, bool rebindImports) {
	if (g_steamHooked || HookAllExports(hSteamApi, hSteamApi) <= 0)
		return;
	HookSteamAPI(hSteamApi);
	if (rebindImports) {
		char path[MAX_PATH]{};
		GetModuleFileNameA(hSteamApi, path, MAX_PATH);
		LOG("[DSE-DLL] %d IAT entries rebound to steam_api trampolines\n",
			RebindImports(PathFindFileNameA(path), hSteamApi));
	}
}

// LoadLibrary hooks
typedef HMODULE(WINAPI *pfn_LoadLibraryA)(LPCSTR);
typedef HMODULE(WINAPI *pfn_LoadLibraryW)(LPCWSTR);
typedef HMODULE(WINAPI *pfn_LoadLibraryExA)(LPCSTR, HANDLE, DWORD);
typedef HMODULE(WINAPI *pfn_LoadLibraryExW)(LPCWSTR, HANDLE, DWORD);
static pfn_LoadLibraryA Orig_LoadLibraryA = nullptr;
static pfn_LoadLibraryW Orig_LoadLibraryW = nullptr;
static pfn_LoadLibraryExA Orig_LoadLibraryExA = nullptr;
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

static bool IsSteamApiDllA(LPCSTR lpFileName) {
	if (!lpFileName)
		return false;
	WCHAR wide[MAX_PATH]{};
	int len = MultiByteToWideChar(CP_ACP, 0, lpFileName, -1, wide, MAX_PATH);
	if (len <= 0)
		return false;
	return IsSteamApiDll(wide);
}

HMODULE WINAPI Hooked_LoadLibraryA(LPCSTR lpLibFileName) {
	HMODULE hMod = Orig_LoadLibraryA(lpLibFileName);
	if (hMod && !g_steamHooked && IsSteamApiDllA(lpLibFileName)) {
		LOG("[DSE-DLL] LoadLibraryA caught: %s\n", lpLibFileName);
		HookSteamApiInPlace(hMod, false);
	}
	return hMod;
}

HMODULE WINAPI Hooked_LoadLibraryW(LPCWSTR lpLibFileName) {
	HMODULE hMod = Orig_LoadLibraryW(lpLibFileName);
	if (hMod && !g_steamHooked && IsSteamApiDll(lpLibFileName)) {
		LOG("[DSE-DLL] LoadLibraryW caught: %ls\n", lpLibFileName);
		HookSteamApiInPlace(hMod, false);
	}
	return hMod;
}

HMODULE WINAPI Hooked_LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile,
									 DWORD dwFlags) {
	HMODULE hMod = Orig_LoadLibraryExA(lpLibFileName, hFile, dwFlags);
	const DWORD kDataFlags = LOAD_LIBRARY_AS_DATAFILE |
							 LOAD_LIBRARY_AS_IMAGE_RESOURCE |
							 LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE;
	if (hMod && !g_steamHooked && IsSteamApiDllA(lpLibFileName) &&
		!(dwFlags & kDataFlags)) {
		LOG("[DSE-DLL] LoadLibraryExA caught: %s\n", lpLibFileName);
		HookSteamApiInPlace(hMod, false);
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
		HookSteamApiInPlace(hMod, false);
	}
	return hMod;
}

// Entry point
static void InitSteamHooks() {
	if (g_config.coldloaderhooks) {
		LOG("[DSE-DLL] Coldloader mode enabled: skipping steam_api64.dll MinHook hooks to protect integrity.\n");
		LoadSteamConfigFromDll(nullptr);
		ResolveSteamPath();
		SetSteamEnvVars();
		return;
	}
	if (g_config.steamApiForward) {
		LOG("[DSE-DLL] steamApiForward enabled: steam_api64 hooks are installed once forwarding is set up\n");
		return;
	}

	HMODULE hExisting = GetModuleHandleW(L"steam_api64.dll");
	if (!hExisting)
		hExisting = GetModuleHandleW(L"steam_api.dll");
	if (hExisting) {
		LOG("[DSE-DLL] steam_api already loaded - hooking now\n");
		HookSteamApiInPlace(hExisting, true);
		return;
	}

	HookApi(L"kernel32.dll", "LoadLibraryA",
			(LPVOID)&Hooked_LoadLibraryA, (LPVOID *)&Orig_LoadLibraryA);
	HookApi(L"kernel32.dll", "LoadLibraryW",
			(LPVOID)&Hooked_LoadLibraryW, (LPVOID *)&Orig_LoadLibraryW);
	HookApi(L"kernel32.dll", "LoadLibraryExA",
			(LPVOID)&Hooked_LoadLibraryExA, (LPVOID *)&Orig_LoadLibraryExA);
	HookApi(L"kernel32.dll", "LoadLibraryExW",
			(LPVOID)&Hooked_LoadLibraryExW, (LPVOID *)&Orig_LoadLibraryExW);
	LOG("[DSE-DLL] LoadLibrary hooks set - waiting for steam_api64.dll\n");
}
