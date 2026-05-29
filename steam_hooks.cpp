#define WIN32_LEAN_AND_MEAN

#include "log.h"
#include "minhook/include/MinHook.h"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <shlwapi.h>
#include <windows.h>

static uint64_t g_fakeSteamID = 76561198000000000ULL; // default SteamID
static bool g_forceOffline = true;                    // default: appear offline
static bool g_steamHooked = false;
static char g_steamPath[MAX_PATH] = {}; // Steam install path (UTF-8)

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

  WCHAR offBuf[16]{};
  GetPrivateProfileStringW(L"main::connectivity", L"offline", L"1", offBuf,
                           ARRAYSIZE(offBuf), mainIniPath);
  g_forceOffline = (offBuf[0] == L'1');
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

  uint32_t appId = 0;
  bool foundInRoot = TryReadAppId(rootAppIdPath, appId);
  bool foundInSettings = !foundInRoot && TryReadAppId(settingsAppIdPath, appId);

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

// VTable state
static void **g_pISteamUserVTable = nullptr;
static void **g_pISteamFriendsVTable = nullptr;

// VTable typedefs
// CSteamID has constructors, so MSVC x64 returns it via hidden pointer in RDX.
typedef void *(*pfn_GetSteamID_vtable)(void *self, void *pOut);
static pfn_GetSteamID_vtable Orig_GetSteamID_vtable = nullptr;

typedef bool (*pfn_BLoggedOn_vtable)(void *);
static pfn_BLoggedOn_vtable Orig_BLoggedOn_vtable = nullptr;

typedef int (*pfn_GetPersonaState_vtable)(void *);
static pfn_GetPersonaState_vtable Orig_GetPersonaState_vtable = nullptr;

static bool Hooked_RestartAppIfNecessary(uint32_t appId) {
  LOG("[DSE-DLL] SteamAPI_RestartAppIfNecessary(%u) -> false\n", appId);
  return false;
}

static uint64_t Hooked_GetSteamID(void *self) {
  uint64_t orig = 0;
  if (Orig_GetSteamID)
    orig = Orig_GetSteamID(self);
  LOG("[DSE-DLL] SteamAPI_ISteamUser_GetSteamID orig=%llu -> %llu\n",
      (unsigned long long)orig, (unsigned long long)g_fakeSteamID);
  return g_fakeSteamID;
}

static bool Hooked_BLoggedOn(void *self) {
  bool orig = Orig_BLoggedOn ? Orig_BLoggedOn(self) : false;
  LOG("[DSE-DLL] SteamAPI_ISteamUser_BLoggedOn orig=%d -> false\n", orig);
  return false;
}

static int Hooked_GetPersonaState(void *self) {
  int orig = Orig_GetPersonaState ? Orig_GetPersonaState(self) : 0;
  int state = g_forceOffline ? 0 : 1;
  LOG("[DSE-DLL] SteamAPI_ISteamFriends_GetPersonaState orig=%d -> %d\n", orig,
      state);
  return state;
}

// VTable hooks
static void *Hooked_GetSteamID_vtable(void *self, uint64_t *pOut) {
  if (Orig_GetSteamID_vtable)
    Orig_GetSteamID_vtable(self, pOut);
  if (pOut) {
    LOG("[DSE-DLL] ISteamUser::GetSteamID() orig=%llu -> %llu\n",
        (unsigned long long)*pOut, (unsigned long long)g_fakeSteamID);
    *pOut = g_fakeSteamID;
  }
  return pOut;
}

static bool Hooked_BLoggedOn_vtable(void *self) {
  bool orig = Orig_BLoggedOn_vtable ? Orig_BLoggedOn_vtable(self) : false;
  LOG("[DSE-DLL] ISteamUser::BLoggedOn() orig=%d -> false\n", orig);
  return false;
}

static int Hooked_GetPersonaState_vtable(void *self) {
  int orig =
      Orig_GetPersonaState_vtable ? Orig_GetPersonaState_vtable(self) : 0;
  int state = g_forceOffline ? 0 : 1;
  LOG("[DSE-DLL] ISteamFriends::GetPersonaState() orig=%d -> %d\n", orig,
      state);
  return state;
}

// Interface hookers
static void HookInterface_ISteamUser(void *pInterface) {
  if (!pInterface)
    return;
  void **vtable = *(void ***)pInterface;
  if (g_pISteamUserVTable == vtable)
    return;
  g_pISteamUserVTable = vtable;
  LOG("[DSE-DLL] Intercepted ISteamUser vtable at %p\n", vtable);

  // Log all slots so we can verify layout if needed
  for (int i = 0; i < 16; i++)
    LOG("[DSE-DLL]   vtable[%d] = %p\n", i, vtable[i]);

  // Find correct slots by matching against flat API exports
  HMODULE hSteamApi = GetModuleHandleW(L"steam_api64.dll");
  if (!hSteamApi)
    hSteamApi = GetModuleHandleW(L"steam_api.dll");

  int getIDSlot = 2;    // fallback
  int loggedOnSlot = 1; // fallback

  if (hSteamApi) {
    void *pFlatGetID =
        (void *)GetProcAddress(hSteamApi, "SteamAPI_ISteamUser_GetSteamID");
    void *pFlatLoggedOn =
        (void *)GetProcAddress(hSteamApi, "SteamAPI_ISteamUser_BLoggedOn");
    for (int i = 0; i < 16; i++) {
      if (pFlatGetID && vtable[i] == pFlatGetID) {
        getIDSlot = i;
        LOG("[DSE-DLL]   GetSteamID -> slot [%d]\n", i);
      }
      if (pFlatLoggedOn && vtable[i] == pFlatLoggedOn) {
        loggedOnSlot = i;
        LOG("[DSE-DLL]   BLoggedOn  -> slot [%d]\n", i);
      }
    }
  }

  MH_CreateHook(vtable[loggedOnSlot], (LPVOID)&Hooked_BLoggedOn_vtable,
                (LPVOID *)&Orig_BLoggedOn_vtable);
  MH_EnableHook(vtable[loggedOnSlot]);
  MH_CreateHook(vtable[getIDSlot], (LPVOID)&Hooked_GetSteamID_vtable,
                (LPVOID *)&Orig_GetSteamID_vtable);
  MH_EnableHook(vtable[getIDSlot]);
}

static void HookInterface_ISteamFriends(void *pInterface) {
  if (!pInterface)
    return;
  void **vtable = *(void ***)pInterface;
  if (g_pISteamFriendsVTable == vtable)
    return;
  g_pISteamFriendsVTable = vtable;
  LOG("[DSE-DLL] Intercepted ISteamFriends vtable at %p\n", vtable);
  MH_CreateHook(vtable[2], (LPVOID)&Hooked_GetPersonaState_vtable,
                (LPVOID *)&Orig_GetPersonaState_vtable);
  MH_EnableHook(vtable[2]);
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
    HookInterface_ISteamUser(p);
  else if (strncmp(pszVersion, "SteamFriends0", 13) == 0)
    HookInterface_ISteamFriends(p);
  return p;
}

// SteamAPI_GetHSteamUser
// Intercept so we can
// force-install the ISteamUser vtable hook the moment the game resolves its
// user handle before it ever calls GetSteamID().
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
        HookInterface_ISteamUser(pUser);
        break;
      }
    }
  }
  return hUser;
}

// Dynamic versioned accessor hooks
#define HOOK_STEAMUSER(ver)                                                    \
  typedef void *(*pfn_SteamUser##ver)();                                       \
  static pfn_SteamUser##ver Orig_SteamUser##ver = nullptr;                     \
  static void *Hooked_SteamUser##ver() {                                       \
    void *p = Orig_SteamUser##ver ? Orig_SteamUser##ver() : nullptr;           \
    HookInterface_ISteamUser(p);                                               \
    return p;                                                                  \
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
  typedef void *(*pfn_SteamFriends##ver)();                                    \
  static pfn_SteamFriends##ver Orig_SteamFriends##ver = nullptr;               \
  static void *Hooked_SteamFriends##ver() {                                    \
    void *p = Orig_SteamFriends##ver ? Orig_SteamFriends##ver() : nullptr;     \
    HookInterface_ISteamFriends(p);                                            \
    return p;                                                                  \
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

// Init hooks
static bool Hooked_SteamAPI_Init() {
  LOG("[DSE-DLL] SteamAPI_Init()\n");
  if (Orig_SteamAPI_Init) {
    bool r = Orig_SteamAPI_Init();
    if (r) {
      LOG("[DSE-DLL]   (real init succeeded)\n");
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
  WCHAR clientPath[MAX_PATH]{};
  lstrcpynW(clientPath, wPath, MAX_PATH);
  PathAppendW(clientPath, L"steamclient64.dll");
  SetEnvironmentVariableW(L"SteamClientDll64", clientPath);
  SetDllDirectoryW(wPath);
  LOG("[DSE-DLL] Set SteamPath env = %s\n", g_steamPath);
}

// Hook all steam_api exports.
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

#define TRY_HOOK(export, fn, orig, label)                                      \
  do {                                                                         \
    auto _p = (LPVOID)GetProcAddress(hSteamApi, export);                       \
    if (_p) {                                                                  \
      MH_STATUS _s = MH_CreateHook(_p, (LPVOID) & fn, (LPVOID *)&orig);        \
      if (_s == MH_OK) {                                                       \
        MH_EnableHook(_p);                                                     \
        LOG("[DSE-DLL]   Hooked " label "\n");                                 \
      } else                                                                   \
        LOG("[DSE-DLL]   Failed to hook " label ": %d\n", _s);                 \
    } else                                                                     \
      LOG("[DSE-DLL]   " label " export not found\n");                         \
  } while (0)

  TRY_HOOK("SteamAPI_RestartAppIfNecessary", Hooked_RestartAppIfNecessary,
           Orig_RestartApp, "RestartAppIfNecessary");
  TRY_HOOK("SteamAPI_ISteamUser_GetSteamID", Hooked_GetSteamID, Orig_GetSteamID,
           "ISteamUser_GetSteamID");
  TRY_HOOK("SteamAPI_ISteamUser_BLoggedOn", Hooked_BLoggedOn, Orig_BLoggedOn,
           "ISteamUser_BLoggedOn");
  TRY_HOOK("SteamAPI_ISteamFriends_GetPersonaState", Hooked_GetPersonaState,
           Orig_GetPersonaState, "ISteamFriends_GetPersonaState");
  TRY_HOOK("SteamAPI_Init", Hooked_SteamAPI_Init, Orig_SteamAPI_Init,
           "SteamAPI_Init");
  TRY_HOOK("SteamAPI_InitFlat", Hooked_SteamAPI_InitFlat,
           Orig_SteamAPI_InitFlat, "SteamAPI_InitFlat");
  TRY_HOOK("SteamInternal_SteamAPI_Init", Hooked_SteamInternal_SteamAPI_Init,
           Orig_SteamInternal_Init, "SteamInternal_SteamAPI_Init");
  TRY_HOOK("SteamAPI_IsSteamRunning", Hooked_IsSteamRunning,
           Orig_IsSteamRunning, "SteamAPI_IsSteamRunning");
  TRY_HOOK("SteamAPI_GetSteamInstallPath", Hooked_GetSteamInstallPath,
           Orig_GetSteamInstallPath, "SteamAPI_GetSteamInstallPath");
  TRY_HOOK("SteamInternal_FindOrCreateUserInterface",
           Hooked_SteamInternal_FindOrCreateUserInterface,
           Orig_FindOrCreateUserInterface,
           "SteamInternal_FindOrCreateUserInterface");

  TRY_HOOK("SteamAPI_GetHSteamUser", Hooked_SteamAPI_GetHSteamUser,
           Orig_GetHSteamUser, "SteamAPI_GetHSteamUser");

#undef TRY_HOOK

#define DO_HOOK_STEAMUSER(ver)                                                 \
  do {                                                                         \
    auto p = (LPVOID)GetProcAddress(hSteamApi, "SteamAPI_SteamUser_v" #ver);   \
    if (p) {                                                                   \
      MH_CreateHook(p, (LPVOID) & Hooked_SteamUser##ver,                       \
                    (LPVOID *)&Orig_SteamUser##ver);                           \
      MH_EnableHook(p);                                                        \
      LOG("[DSE-DLL]   Hooked SteamAPI_SteamUser_v" #ver "\n");                \
    }                                                                          \
  } while (0)

  DO_HOOK_STEAMUSER(015);
  DO_HOOK_STEAMUSER(016);
  DO_HOOK_STEAMUSER(017);
  DO_HOOK_STEAMUSER(018);
  DO_HOOK_STEAMUSER(019);
  DO_HOOK_STEAMUSER(020);
  DO_HOOK_STEAMUSER(021);
  DO_HOOK_STEAMUSER(022);
  DO_HOOK_STEAMUSER(023);
  DO_HOOK_STEAMUSER(024);
  DO_HOOK_STEAMUSER(025);

#define DO_HOOK_STEAMFRIENDS(ver)                                              \
  do {                                                                         \
    auto p =                                                                   \
        (LPVOID)GetProcAddress(hSteamApi, "SteamAPI_SteamFriends_v" #ver);     \
    if (p) {                                                                   \
      MH_CreateHook(p, (LPVOID) & Hooked_SteamFriends##ver,                    \
                    (LPVOID *)&Orig_SteamFriends##ver);                        \
      MH_EnableHook(p);                                                        \
      LOG("[DSE-DLL]   Hooked SteamAPI_SteamFriends_v" #ver "\n");             \
    }                                                                          \
  } while (0)

  DO_HOOK_STEAMFRIENDS(010);
  DO_HOOK_STEAMFRIENDS(011);
  DO_HOOK_STEAMFRIENDS(012);
  DO_HOOK_STEAMFRIENDS(013);
  DO_HOOK_STEAMFRIENDS(014);
  DO_HOOK_STEAMFRIENDS(015);
  DO_HOOK_STEAMFRIENDS(016);
  DO_HOOK_STEAMFRIENDS(017);
  DO_HOOK_STEAMFRIENDS(018);
  DO_HOOK_STEAMFRIENDS(019);
  DO_HOOK_STEAMFRIENDS(020);

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
    HookSteamAPI(hMod);
  }
  return hMod;
}

HMODULE WINAPI Hooked_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile,
                                     DWORD dwFlags) {
  HMODULE hMod = Orig_LoadLibraryExW(lpLibFileName, hFile, dwFlags);
  if (hMod && !g_steamHooked && IsSteamApiDll(lpLibFileName)) {
    LOG("[DSE-DLL] LoadLibraryExW caught: %ls\n", lpLibFileName);
    HookSteamAPI(hMod);
  }
  return hMod;
}

// Entry point
static void InitSteamHooks() {
  HMODULE hExisting = GetModuleHandleW(L"steam_api64.dll");
  if (!hExisting)
    hExisting = GetModuleHandleW(L"steam_api.dll");
  if (hExisting) {
    LOG("[DSE-DLL] steam_api already loaded - hooking now\n");
    HookSteamAPI(hExisting);
    return;
  }
  MH_CreateHookApi(L"kernel32.dll", "LoadLibraryW",
                   (LPVOID)&Hooked_LoadLibraryW, (LPVOID *)&Orig_LoadLibraryW);
  MH_CreateHookApi(L"kernel32.dll", "LoadLibraryExW",
                   (LPVOID)&Hooked_LoadLibraryExW,
                   (LPVOID *)&Orig_LoadLibraryExW);
  MH_EnableHook(MH_ALL_HOOKS);
  LOG("[DSE-DLL] LoadLibrary hooks set - waiting for steam_api64.dll\n");
}
