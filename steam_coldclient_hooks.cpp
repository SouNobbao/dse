#pragma once
#include "config.h"
#include "log.h"
#include "minhook/include/MinHook.h"
#include "peb_struct.h"
#include <shlwapi.h>
#include <strsafe.h>
#include <windows.h>

static void HookInterface_ISteamClient(void *pInterface, const char *pszVersion);
static void HookSteamInterfaceByVersion(void *pInterface, const char *pszVersion);
static void LoadSteamConfigFromDll(HMODULE hSteamApi);

static UNICODE_STRING g_origBaseDllName{};
static UNICODE_STRING g_origFullDllName{};

static void RenameLdrEntry(HMODULE hModule, LPCWSTR newName, bool isRestore) {
	PEB_CUSTOM *pPEB = (PEB_CUSTOM *)__readgsqword(0x60);
	USHORT newLen = (USHORT)(wcslen(newName) * sizeof(WCHAR));

	auto rename = [&](_LIST_ENTRY *head, size_t linkOffset) {
		for (_LIST_ENTRY *p = head->Flink; p != head; p = p->Flink) {
			auto *entry = (_LDR_DATA_TABLE_ENTRY_CUSTOM *)((BYTE *)p - linkOffset);
			if (entry->DllBase == (PVOID)hModule) {
				if (!isRestore) {
					if (g_origBaseDllName.Buffer == nullptr) {
						g_origBaseDllName = entry->BaseDllName;
						g_origFullDllName = entry->FullDllName;
					}
					entry->BaseDllName.Buffer = (PWSTR)newName;
					entry->BaseDllName.Length = newLen;
					entry->BaseDllName.MaximumLength = newLen + sizeof(WCHAR);

					entry->FullDllName.Buffer = (PWSTR)newName;
					entry->FullDllName.Length = newLen;
					entry->FullDllName.MaximumLength = newLen + sizeof(WCHAR);
				} else {
					if (g_origBaseDllName.Buffer != nullptr) {
						entry->BaseDllName = g_origBaseDllName;
						entry->FullDllName = g_origFullDllName;
					} else {
						entry->BaseDllName.Buffer = (PWSTR)newName;
						entry->BaseDllName.Length = newLen;
						entry->BaseDllName.MaximumLength = newLen + sizeof(WCHAR);
					}
				}
				return;
			}
		}
	};

	rename(&pPEB->Ldr->InLoadOrderModuleList,
		   offsetof(LDR_DATA_TABLE_ENTRY_CUSTOM, InLoadOrderLinks));
	rename(&pPEB->Ldr->InMemoryOrderModuleList,
		   offsetof(LDR_DATA_TABLE_ENTRY_CUSTOM, InMemoryOrderLinks));
	rename(&pPEB->Ldr->InInitializationOrderModuleList,
		   offsetof(LDR_DATA_TABLE_ENTRY_CUSTOM, InInitializationOrderLinks));

	LOG("[DSE-DLL] Renamed LDR entry for %p to %ls\n", hModule, newName);
}

static void HideLdrEntry(HMODULE hModule) {
	PEB_CUSTOM *pPEB = (PEB_CUSTOM *)__readgsqword(0x60);

	auto hide = [&](_LIST_ENTRY *head, size_t linkOffset) {
		for (_LIST_ENTRY *p = head->Flink; p != head; p = p->Flink) {
			auto *entry = (_LDR_DATA_TABLE_ENTRY_CUSTOM *)((BYTE *)p - linkOffset);
			if (entry->DllBase == (PVOID)hModule) {
				_LIST_ENTRY *links = (_LIST_ENTRY *)((BYTE *)entry + linkOffset);
				links->Blink->Flink = links->Flink;
				links->Flink->Blink = links->Blink;
				return true;
			}
		}
		return false;
	};

	hide(&pPEB->Ldr->InLoadOrderModuleList, offsetof(LDR_DATA_TABLE_ENTRY_CUSTOM, InLoadOrderLinks));
	hide(&pPEB->Ldr->InMemoryOrderModuleList, offsetof(LDR_DATA_TABLE_ENTRY_CUSTOM, InMemoryOrderLinks));
	hide(&pPEB->Ldr->InInitializationOrderModuleList, offsetof(LDR_DATA_TABLE_ENTRY_CUSTOM, InInitializationOrderLinks));

	LOG("[DSE-DLL] Hid LDR entry for %p\n", hModule);
}

extern HMODULE g_hModule;

static HMODULE g_hEmulatorClient = nullptr;
static HMODULE g_hRealSteamClient = nullptr;

static bool GetSteamInstallPath(WCHAR *out, DWORD maxChars) {
	DWORD size = maxChars * sizeof(WCHAR);
	if (RegGetValueW(HKEY_CURRENT_USER, L"Software\\Valve\\Steam",
					 L"SteamPath", RRF_RT_REG_SZ, NULL, out, &size) == ERROR_SUCCESS &&
		out[0])
		return true;
	size = maxChars * sizeof(WCHAR);
	if (RegGetValueW(HKEY_LOCAL_MACHINE, L"Software\\Valve\\Steam",
					 L"InstallPath", RRF_RT_REG_SZ, NULL, out, &size) == ERROR_SUCCESS &&
		out[0])
		return true;
	return false;
}

static void *AllocateEatTrampolines(HMODULE hModule, size_t size, DWORD imageSize) {
	uintptr_t baseAddr = (uintptr_t)hModule;
	uintptr_t maxAddr = baseAddr + 0xFFFFFFFFull;

	SYSTEM_INFO si;
	GetSystemInfo(&si);
	uintptr_t granularity = si.dwAllocationGranularity;
	uintptr_t currentAddr = baseAddr + imageSize;
	currentAddr = (currentAddr + granularity - 1) & ~(granularity - 1);

	while (currentAddr >= baseAddr && currentAddr <= maxAddr) {
		if (size > (size_t)(maxAddr - currentAddr + 1))
			break;
		void *p = VirtualAlloc((void *)currentAddr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (p) {
			uintptr_t pAddr = (uintptr_t)p;
			uint64_t rva = (uint64_t)(pAddr - baseAddr);
			if (pAddr >= baseAddr && rva <= 0xFFFFFFFFull &&
				size <= (size_t)(0x100000000ull - rva)) {
				return p;
			}
			VirtualFree(p, 0, MEM_RELEASE);
		}
		if (currentAddr > maxAddr - granularity)
			break;
		currentAddr += granularity;
	}

	return nullptr;
}

static bool CopyWidePath(WCHAR *dst, size_t dstChars, LPCWSTR src, const char *label) {
	if (!dst || dstChars == 0 || !src)
		return false;
	HRESULT hr = StringCchCopyW(dst, dstChars, src);
	if (FAILED(hr)) {
		LOG("[DSE-DLL] Path too long while copying %s\n", label ? label : "path");
		dst[0] = L'\0';
		return false;
	}
	return true;
}

static bool GetConfiguredSteamDir(WCHAR *steamDir, size_t steamDirChars) {
	if (!steamDir || steamDirChars == 0)
		return false;

	steamDir[0] = L'\0';
	if (g_config.coldloaderhooks && g_config.steam_path && string_length(g_config.steam_path) > 0) {
		wchar_t *tmp = string_to_unicode(string_c_str(g_config.steam_path));
		if (!tmp)
			return false;
		bool copied = CopyWidePath(steamDir, steamDirChars, tmp, "configured steam_path");
		free(tmp);
		if (!copied)
			return false;
	} else if (!GetSteamInstallPath(steamDir, (DWORD)steamDirChars)) {
		LOG("[DSE-DLL] Cannot find Steam install path in registry\n");
		return false;
	}

	for (WCHAR *p = steamDir; *p; p++)
		if (*p == L'/')
			*p = L'\\';
	return true;
}

typedef void *(*tCreateInterface)(const char *pName, int *pReturnCode);
static tCreateInterface g_pRealCreateInterface = nullptr;

typedef void *(*tSteamInternal_CreateInterface)(const char *pName);
static tSteamInternal_CreateInterface g_pRealSteamInternal_CreateInterface = nullptr;

static void *hkCreateInterface(const char *pName, int *pReturnCode) {
	void *p = g_pRealCreateInterface ? g_pRealCreateInterface(pName, pReturnCode) : nullptr;
	LOG("[DSE-DLL] CreateInterface(%s) -> %p\n", pName ? pName : "(null)", p);
	if (p && pName) {
		if (strncmp(pName, "SteamClient", 11) == 0) {
			HookInterface_ISteamClient(p, pName);
		} else {
			HookSteamInterfaceByVersion(p, pName);
		}
	}
	return p;
}

static void *hkSteamInternal_CreateInterface(const char *pName) {
	void *p = g_pRealSteamInternal_CreateInterface ? g_pRealSteamInternal_CreateInterface(pName) : nullptr;
	LOG("[DSE-DLL] SteamInternal_CreateInterface(%s) -> %p\n", pName ? pName : "(null)", p);
	if (p && pName) {
		if (strncmp(pName, "SteamClient", 11) == 0) {
			HookInterface_ISteamClient(p, pName);
		} else {
			HookSteamInterfaceByVersion(p, pName);
		}
	}
	return p;
}

static int HookAllExports(HMODULE hSource, HMODULE hTarget) {
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hSource;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE)
		return 0;

	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)hSource + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	auto &expEntry = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (!expEntry.VirtualAddress)
		return 0;

	auto *expDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE *)hSource + expEntry.VirtualAddress);
	DWORD *names = (DWORD *)((BYTE *)hSource + expDir->AddressOfNames);
	WORD *ords = (WORD *)((BYTE *)hSource + expDir->AddressOfNameOrdinals);
	DWORD *funcs = (DWORD *)((BYTE *)hSource + expDir->AddressOfFunctions);

	int hooked = 0, skipped = 0, failed = 0;

	size_t trampolineBytes = expDir->NumberOfNames * 14;
	BYTE *trampolineBase = (BYTE *)AllocateEatTrampolines(hSource, trampolineBytes,
														 nt->OptionalHeader.SizeOfImage);
	BYTE *trampolines = trampolineBase;
	if (!trampolines) {
		LOG("[DSE-DLL] Failed to allocate EAT trampolines above source module base!\n");
		return 0;
	}
	LOG("[DSE-DLL] EAT trampolines allocated at %p (source=%p, rva=0x%llX)\n",
		trampolines, hSource, (unsigned long long)((uintptr_t)trampolines - (uintptr_t)hSource));

	DWORD oldProt;
	if (!VirtualProtect(funcs, expDir->NumberOfFunctions * sizeof(DWORD), PAGE_READWRITE, &oldProt)) {
		LOG("[DSE-DLL] VirtualProtect on EAT failed: %lu\n", GetLastError());
		VirtualFree(trampolineBase, 0, MEM_RELEASE);
		return 0;
	}
	for (DWORD i = 0; i < expDir->NumberOfNames; i++) {
		const char *name = (const char *)((BYTE *)hSource + names[i]);

		if (strcmp(name, "SteamAPI_ISteamAppTicket_GetAppOwnershipTicketData") == 0 ||
			strcmp(name, "SteamAPI_ISteamAppTicket_GetTicketB2C") == 0) {
			LOG("[DSE-DLL] Ignoring export %s\n", name);
			skipped++;
			continue;
		}

		DWORD rva = funcs[ords[i]];

		if (rva >= expEntry.VirtualAddress && rva < expEntry.VirtualAddress + expEntry.Size)
			continue;

		void *dst = (void *)GetProcAddress(hTarget, name);

		if (!dst) {
			skipped++;
			continue;
		}

		if (strcmp(name, "CreateInterface") == 0) {
			g_pRealCreateInterface = (tCreateInterface)dst;
			dst = (void *)&hkCreateInterface;
			LOG("[DSE-DLL] Intercepted CreateInterface export for coldloader interface wrapping\n");
		} else if (strcmp(name, "SteamInternal_CreateInterface") == 0) {
			g_pRealSteamInternal_CreateInterface = (tSteamInternal_CreateInterface)dst;
			dst = (void *)&hkSteamInternal_CreateInterface;
			LOG("[DSE-DLL] Intercepted SteamInternal_CreateInterface export for coldloader interface wrapping\n");
		}

		trampolines[0] = 0xFF;
		trampolines[1] = 0x25;
		trampolines[2] = 0x00;
		trampolines[3] = 0x00;
		trampolines[4] = 0x00;
		trampolines[5] = 0x00;
		*(void **)(&trampolines[6]) = dst;

		uintptr_t delta = (uintptr_t)trampolines - (uintptr_t)hSource;
		if ((uintptr_t)trampolines < (uintptr_t)hSource || delta > 0xFFFFFFFFull) {
			LOG("[DSE-DLL] Failed to hook export %s: trampoline %p is not encodable as EAT RVA\n",
				name, trampolines);
			failed++;
			trampolines += 14;
			continue;
		}

		DWORD newRva = (DWORD)delta;
		funcs[ords[i]] = newRva;

		trampolines += 14;
		hooked++;
	}

	VirtualProtect(funcs, expDir->NumberOfFunctions * sizeof(DWORD), oldProt, &oldProt);
	DWORD trampOldProt = 0;
	FlushInstructionCache(GetCurrentProcess(), trampolineBase, trampolineBytes);
	if (!VirtualProtect(trampolineBase, trampolineBytes, PAGE_EXECUTE_READ, &trampOldProt)) {
		LOG("[DSE-DLL] Failed to set EAT trampolines RX: %lu\n", GetLastError());
	}

	LOG("[DSE-DLL] Export forwarding : %d hooked, %d skipped, %d failed\n",
		hooked, skipped, failed);
	return hooked;
}

typedef HMODULE(WINAPI *fnLoadLibraryExW)(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
static fnLoadLibraryExW oLoadLibraryExW = nullptr;

static volatile LONG s_steam_hook_state = 0; // 0 = not started, 1 = in progress, 2 = ready

static void SetupSteamClientForwarding(HMODULE hEmulator) {
	if (!hEmulator)
		return;
	if (InterlockedCompareExchange(&s_steam_hook_state, 1, 0) != 0)
		return;

	bool setupOk = false;

	LPCWSTR dllName = L"steamclient64.dll";
	g_hEmulatorClient = hEmulator;

	WCHAR loadedPath[MAX_PATH] = {0};
	GetModuleFileNameW(hEmulator, loadedPath, MAX_PATH);
	LOG("[DSE-DLL] %ls emulator loaded at %p\n", dllName, hEmulator);
	LOG("[DSE-DLL] Steam emulator path: %ls\n", loadedPath);

	LoadSteamConfigFromDll(hEmulator);

	WCHAR steamDir[MAX_PATH]{};
	WCHAR realPath[MAX_PATH]{};
	WCHAR fakeDllName[64]{};
	WCHAR tempPath[MAX_PATH]{};
	fnLoadLibraryExW pLoadLib = oLoadLibraryExW ? oLoadLibraryExW : (fnLoadLibraryExW)&LoadLibraryExW;
	HMODULE hReal = nullptr;
	int count = 0;
	bool aliasCreated = false;

	if (!GetConfiguredSteamDir(steamDir, ARRAYSIZE(steamDir)))
		goto done;

	if (!PathCombineW(realPath, steamDir, dllName)) {
		LOG("[DSE-DLL] Steam client path is too long\n");
		goto done;
	}

	if (GetFileAttributesW(realPath) == INVALID_FILE_ATTRIBUTES) {
		LOG("[DSE-DLL] Steam %ls not found: %ls\n", dllName, realPath);
		goto done;
	}
	LOG("[DSE-DLL] Steam %ls: %ls\n", dllName, realPath);

	if (FAILED(StringCchPrintfW(fakeDllName, ARRAYSIZE(fakeDllName),
								L"steamclient64_valve.dll"))) {
		LOG("[DSE-DLL] Failed to build real Steam DLL alias name\n");
		goto done;
	}

	if (!PathCombineW(tempPath, steamDir, fakeDllName)) {
		LOG("[DSE-DLL] Real Steam DLL alias path is too long\n");
		goto done;
	}

	if (GetFileAttributesW(tempPath) == INVALID_FILE_ATTRIBUTES) {
		if (!CreateHardLinkW(tempPath, realPath, NULL)) {
			DWORD hardlinkErr = GetLastError();
			LOG("[DSE-DLL] Failed to create hard link for real Steam DLL: %lu\n", hardlinkErr);
			if (!CopyFileW(realPath, tempPath, FALSE)) {
				LOG("[DSE-DLL] Fallback copy also failed: %lu\n", GetLastError());
				goto done;
			}
		}
		aliasCreated = true;
	} else {
		LOG("[DSE-DLL] Reusing existing real Steam DLL alias: %ls\n", tempPath);
	}

	hReal = pLoadLib(tempPath, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
	if (!hReal) {
		LOG("[DSE-DLL] Failed to load temp Steam DLL: %lu\n", GetLastError());
		goto done;
	}
	LOG("[DSE-DLL] Steam loaded at %p from %ls\n", hReal, tempPath);
	if (aliasCreated && !MoveFileExW(tempPath, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT)) {
		LOG("[DSE-DLL] Could not schedule Steam DLL alias cleanup: %lu\n", GetLastError());
	}
	g_hRealSteamClient = hReal;

	if (!g_config.coldloaderhooks) {
		RenameLdrEntry(hEmulator, dllName, true);
	}

	count = HookAllExports(hEmulator, hReal);
	if (count > 0) {
		MH_EnableHook(MH_ALL_HOOKS);
		LOG("[DSE-DLL] %d emulator exports now forwarding to real %ls\n", count, dllName);
	} else {
		LOG("[DSE-DLL] No exports hooked for %ls!\n", dllName);
	}
	HideLdrEntry(hReal);
	setupOk = count > 0;

	if (g_config.coldloaderhooks && g_pRealCreateInterface) {
		const char *client_versions[] = {"SteamClient021", "SteamClient020", "SteamClient019", "SteamClient018", "SteamClient017", "SteamClient016", "SteamClient015", nullptr};
		for (int i = 0; client_versions[i]; i++) {
			int code = 0;
			void *pClient = g_pRealCreateInterface(client_versions[i], &code);
			if (pClient) {
				LOG("[DSE-DLL] Pre-hooked existing ISteamClient via %s @ %p\n", client_versions[i], pClient);
				HookInterface_ISteamClient(pClient, client_versions[i]);
				break;
			}
		}
	}

done:
	InterlockedExchange(&s_steam_hook_state, setupOk ? 2 : 0);
	if (!setupOk) {
		g_hRealSteamClient = nullptr;
		LOG("[DSE-DLL] Steam client forwarding setup did not complete; will retry on next load\n");
	}
}

static HMODULE WINAPI hkLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
	bool redirected = false;
	WCHAR emuPath[MAX_PATH] = {0};
	LPCWSTR targetPath = lpLibFileName;

	bool isSteamClient = lpLibFileName && StrStrIW(lpLibFileName, L"steamclient64.dll");
	bool isOverlay = lpLibFileName && StrStrIW(lpLibFileName, L"gameoverlayrenderer64.dll");

	static bool s_overlay_hooked = false;

	if (!g_config.coldloaderhooks &&
		InterlockedCompareExchange(&s_steam_hook_state, 0, 0) == 0 && isSteamClient) {
		GetModuleFileNameW(g_hModule, emuPath, MAX_PATH);
		PathRemoveFileSpecW(emuPath);
		if (!PathAppendW(emuPath, L"steamclient64.dll")) {
			emuPath[0] = L'\0';
		}

		if (emuPath[0] && GetFileAttributesW(emuPath) != INVALID_FILE_ATTRIBUTES) {
			targetPath = emuPath;
			dwFlags |= LOAD_WITH_ALTERED_SEARCH_PATH;
			dwFlags &= ~0x00000080;
			redirected = true;
			LOG("[DSE-DLL] Redirecting LoadLibraryExW -> %ls (dwFlags=0x%x)\n", emuPath, dwFlags);
		}
	}

	static WCHAR overlayRealPath[MAX_PATH] = {0};
	if (isOverlay && !s_overlay_hooked) {
		if (overlayRealPath[0] == 0) {
			WCHAR steamDir[MAX_PATH]{};
			if (GetConfiguredSteamDir(steamDir, ARRAYSIZE(steamDir))) {
				if (!PathCombineW(overlayRealPath, steamDir, L"gameoverlayrenderer64.dll")) {
					overlayRealPath[0] = L'\0';
				}
			}
		}

		if (GetFileAttributesW(overlayRealPath) != INVALID_FILE_ATTRIBUTES) {
			targetPath = overlayRealPath;
			dwFlags |= LOAD_WITH_ALTERED_SEARCH_PATH;
			s_overlay_hooked = true;
			LOG("[DSE-DLL] Redirecting gameoverlayrenderer64.dll to valve : %ls\n", targetPath);
		}
	}

	LOG("[DSE-DLL] LoadLibraryExW called for: %ls\n", targetPath);
	HMODULE hModule = oLoadLibraryExW(targetPath, hFile, dwFlags);

	if (!hModule && redirected) {
		LOG("[DSE-DLL] Redirected LoadLibraryExW failed! GetLastError = %lu\n", GetLastError());
	}

	if (hModule && isSteamClient &&
		InterlockedCompareExchange(&s_steam_hook_state, 0, 0) == 0) {
		SetupSteamClientForwarding(hModule);
	}
	return hModule;
}

typedef FARPROC(WINAPI *fnGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
static fnGetProcAddress oGetProcAddress = nullptr;

static FARPROC WINAPI hkGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
	FARPROC proc = oGetProcAddress(hModule, lpProcName);
	if (!proc && hModule && hModule == g_hEmulatorClient && g_hRealSteamClient != nullptr) {
		proc = oGetProcAddress(g_hRealSteamClient, lpProcName);
		if (proc && ((ULONG_PTR)lpProcName > 0xFFFF)) {
			LOG("[DSE-DLL] GetProcAddress forwarded %s to real steamclient\n", lpProcName);
		}
	}
	bool isSteamClientModule =
		hModule && (hModule == g_hEmulatorClient || hModule == g_hRealSteamClient);
	if (proc && isSteamClientModule && ((ULONG_PTR)lpProcName > 0xFFFF)) {
		if (strcmp(lpProcName, "CreateInterface") == 0) {
			if (g_pRealCreateInterface == nullptr) {
				if (hModule == g_hRealSteamClient && proc != (FARPROC)&hkCreateInterface) {
					g_pRealCreateInterface = (tCreateInterface)proc;
				} else if (g_hRealSteamClient) {
					g_pRealCreateInterface =
						(tCreateInterface)oGetProcAddress(g_hRealSteamClient, lpProcName);
				}
			}
			if (g_pRealCreateInterface)
				return (FARPROC)&hkCreateInterface;
		}
		if (strcmp(lpProcName, "SteamInternal_CreateInterface") == 0) {
			if (g_pRealSteamInternal_CreateInterface == nullptr) {
				if (hModule == g_hRealSteamClient &&
					proc != (FARPROC)&hkSteamInternal_CreateInterface) {
					g_pRealSteamInternal_CreateInterface = (tSteamInternal_CreateInterface)proc;
				} else if (g_hRealSteamClient) {
					g_pRealSteamInternal_CreateInterface =
						(tSteamInternal_CreateInterface)oGetProcAddress(g_hRealSteamClient, lpProcName);
				}
			}
			if (g_pRealSteamInternal_CreateInterface)
				return (FARPROC)&hkSteamInternal_CreateInterface;
		}
	}
	return proc;
}

void InitSteamColdHooks() {
	HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
	HMODULE hKernelBase = GetModuleHandleW(L"kernelbase.dll");
	void *pLoadLib = nullptr;
	if (hKernelBase)
		pLoadLib = (void *)GetProcAddress(hKernelBase, "LoadLibraryExW");
	if (!pLoadLib && hKernel32)
		pLoadLib = (void *)GetProcAddress(hKernel32, "LoadLibraryExW");

	if (pLoadLib) {
		MH_CreateHook(pLoadLib, (void *)hkLoadLibraryExW, (void **)&oLoadLibraryExW);
		MH_EnableHook(pLoadLib);
		LOG("[DSE-DLL] Hooked LoadLibraryExW to intercept steamclient64.dll\n");
	}

	void *pGetProcAddr = nullptr;
	if (hKernelBase)
		pGetProcAddr = (void *)GetProcAddress(hKernelBase, "GetProcAddress");
	if (!pGetProcAddr && hKernel32)
		pGetProcAddr = (void *)GetProcAddress(hKernel32, "GetProcAddress");

	if (pGetProcAddr) {
		MH_CreateHook(pGetProcAddr, (void *)hkGetProcAddress, (void **)&oGetProcAddress);
		MH_EnableHook(pGetProcAddr);
		LOG("[DSE-DLL] Hooked GetProcAddress for steamclient internal exports\n");
	}

	HMODULE hExistingClient = GetModuleHandleW(L"steamclient64.dll");
	if (hExistingClient) {
		LOG("[DSE-DLL] steamclient64.dll already in memory at %p - setting up forwarding\n", hExistingClient);
		SetupSteamClientForwarding(hExistingClient);
	}
}
