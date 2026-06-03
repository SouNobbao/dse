#pragma once
#include "config.h"
#include "log.h"
#include "minhook/include/MinHook.h"
#include "peb_struct.h"
#include <shlwapi.h>
#include <windows.h>

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

static void *AllocateTrampolines(HMODULE hModule, size_t size) {
	uintptr_t baseAddr = (uintptr_t)hModule;
	uintptr_t minAddr = baseAddr > 0x7FFFFFFF ? baseAddr - 0x7FFFFFFF : 0;
	uintptr_t maxAddr = baseAddr + 0x7FFFFFFF;

	SYSTEM_INFO si;
	GetSystemInfo(&si);
	uintptr_t currentAddr = baseAddr + 0x10000;

	while (currentAddr < maxAddr) {
		void *p = VirtualAlloc((void *)currentAddr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (p)
			return p;
		currentAddr += si.dwAllocationGranularity;
	}

	currentAddr = baseAddr - 0x10000;
	while (currentAddr > minAddr) {
		void *p = VirtualAlloc((void *)currentAddr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (p)
			return p;
		currentAddr -= si.dwAllocationGranularity;
	}

	return nullptr;
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

	BYTE *trampolines = (BYTE *)AllocateTrampolines(hSource, expDir->NumberOfNames * 14);
	if (!trampolines) {
		LOG("[DSE-DLL] Failed to allocate EAT trampolines!\n");
		return 0;
	}

	DWORD oldProt;
	VirtualProtect(funcs, expDir->NumberOfFunctions * sizeof(DWORD), PAGE_READWRITE, &oldProt);

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

		trampolines[0] = 0xFF;
		trampolines[1] = 0x25;
		trampolines[2] = 0x00;
		trampolines[3] = 0x00;
		trampolines[4] = 0x00;
		trampolines[5] = 0x00;
		*(void **)(&trampolines[6]) = dst;

		DWORD newRva = (DWORD)((BYTE *)trampolines - (BYTE *)hSource);
		funcs[ords[i]] = newRva;

		trampolines += 14;
		hooked++;
	}

	VirtualProtect(funcs, expDir->NumberOfFunctions * sizeof(DWORD), oldProt, &oldProt);

	LOG("[DSE-DLL] Export forwarding : %d hooked, %d skipped, %d failed\n",
		hooked, skipped, failed);
	return hooked;
}

typedef HMODULE(WINAPI *fnLoadLibraryExW)(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
static fnLoadLibraryExW oLoadLibraryExW = nullptr;

static HMODULE WINAPI hkLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
	bool redirected = false;
	WCHAR emuPath[MAX_PATH] = {0};
	LPCWSTR targetPath = lpLibFileName;

	bool isSteamClient = lpLibFileName && StrStrIW(lpLibFileName, L"steamclient64.dll");
	bool isOverlay = lpLibFileName && StrStrIW(lpLibFileName, L"gameoverlayrenderer64.dll");

	static bool s_steam_hooked = false;
	static bool s_overlay_hooked = false;

	if (!g_config.coldloaderhooks && !s_steam_hooked && isSteamClient) {
		GetModuleFileNameW(g_hModule, emuPath, MAX_PATH);
		PathRemoveFileSpecW(emuPath);
		PathAppendW(emuPath, L"steamclient64.dll");

		if (GetFileAttributesW(emuPath) != INVALID_FILE_ATTRIBUTES) {
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
			WCHAR steamDir[MAX_PATH];
			if (g_config.coldloaderhooks && !g_config.steam_path.empty()) {
				lstrcpyW(steamDir, g_config.steam_path.c_str());
			} else {
				GetSteamInstallPath(steamDir, MAX_PATH);
			}
			for (WCHAR *p = steamDir; *p; p++)
				if (*p == L'/')
					*p = L'\\';
			PathCombineW(overlayRealPath, steamDir, L"gameoverlayrenderer64.dll");
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

	if (hModule && (isSteamClient && !s_steam_hooked)) {
		s_steam_hooked = true;

		LPCWSTR dllName = L"steamclient64.dll";
		LPCWSTR fakeDllName = L"steamclient64_valve.dll";

		HMODULE hEmulator = hModule;
		g_hEmulatorClient = hModule;

		WCHAR loadedPath[MAX_PATH] = {0};
		GetModuleFileNameW(hModule, loadedPath, MAX_PATH);
		LOG("[DSE-DLL] %ls emulator loaded at %p\n", dllName, hEmulator);
		LOG("[DSE-DLL] Steam emulator path: %ls\n", loadedPath);

		WCHAR steamDir[MAX_PATH];
		if (g_config.coldloaderhooks && !g_config.steam_path.empty()) {
			lstrcpyW(steamDir, g_config.steam_path.c_str());
		} else if (!GetSteamInstallPath(steamDir, MAX_PATH)) {
			LOG("[DSE-DLL] Cannot find Steam install path in registry\n");
			return hModule;
		}

		for (WCHAR *p = steamDir; *p; p++)
			if (*p == L'/')
				*p = L'\\';

		WCHAR realPath[MAX_PATH];
		PathCombineW(realPath, steamDir, dllName);

		if (GetFileAttributesW(realPath) == INVALID_FILE_ATTRIBUTES) {
			LOG("[DSE-DLL] Steam %ls not found: %ls\n", dllName, realPath);
			return hModule;
		}
		LOG("[DSE-DLL] Steam %ls: %ls\n", dllName, realPath);

		WCHAR tempPath[MAX_PATH];
		lstrcpyW(tempPath, steamDir);
		PathAppendW(tempPath, fakeDllName);

		DeleteFileW(tempPath);
		if (!CreateHardLinkW(tempPath, realPath, NULL)) {
			LOG("[DSE-DLL] Failed to create hard link for real Steam DLL: %lu\n", GetLastError());
			if (!CopyFileW(realPath, tempPath, FALSE)) {
				LOG("[DSE-DLL] Fallback copy also failed: %lu\n", GetLastError());
				return hModule;
			}
		}

		HMODULE hReal = oLoadLibraryExW(tempPath, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
		if (!hReal) {
			LOG("[DSE-DLL] Failed to load temp Steam DLL: %lu\n", GetLastError());
			return hModule;
		}
		LOG("[DSE-DLL] Steam loaded at %p from %ls\n", hReal, tempPath);
		if (isSteamClient)
			g_hRealSteamClient = hReal;

		if (!g_config.coldloaderhooks) {
			RenameLdrEntry(hEmulator, dllName, true);
		}
		HideLdrEntry(hReal);

		int count = HookAllExports(hEmulator, hReal);
		if (count > 0) {
			MH_EnableHook(MH_ALL_HOOKS);
			LOG("[DSE-DLL] %d emulator exports now forwarding to real %ls\n", count, dllName);
		} else {
			LOG("[DSE-DLL] No exports hooked for %ls!\n", dllName);
		}
	}
	return hModule;
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
}
