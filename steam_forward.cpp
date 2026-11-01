#pragma once
#include "config.h"
#include "log.h"
#include "minhook/include/MinHook.h"
#include "peb_struct.h"
#include "steam_forwarding.h"
#include <shlwapi.h>
#include <windows.h>

// The emulator lives in steam_api64.dll; the real Valve DLL sits next to it as
// steam_api64_o.dll. Same scheme as steamclient64: every emulator export is
// forwarded to the real one, and the real module is hidden from module walks.
// Reuses HookAllExports/HideLdrEntry from steam_coldclient_hooks.cpp.

static volatile LONG s_api_forward_state = 0; // 0 = not started, 1 = in progress, 2 = ready

// The EAT rewrite only reaches lookups made from now on. Modules that imported
// the emulator statically were bound before we got here, so repoint their IATs
// at the emulator's trampolines, which lead to the hooks or the real DLL.
static int RebindImports(LPCSTR dllName, HMODULE hEmulator) {
	PEB_CUSTOM *pPEB = (PEB_CUSTOM *)__readgsqword(0x60);
	_LIST_ENTRY *head = &pPEB->Ldr->InLoadOrderModuleList;
	int rebound = 0;

	for (_LIST_ENTRY *p = head->Flink; p != head; p = p->Flink) {
		auto *entry = (_LDR_DATA_TABLE_ENTRY_CUSTOM *)p; // InLoadOrderLinks is the first field
		BYTE *base = (BYTE *)entry->DllBase;
		if (!base || base == (BYTE *)hEmulator)
			continue;

		auto *nt = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
		auto &dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (!dir.VirtualAddress)
			continue;

		for (auto *imp = (PIMAGE_IMPORT_DESCRIPTOR)(base + dir.VirtualAddress); imp->Name; imp++) {
			// Without the name table there is nothing to resolve against the real DLL.
			if (_stricmp((const char *)(base + imp->Name), dllName) != 0 || !imp->OriginalFirstThunk)
				continue;

			auto *names = (PIMAGE_THUNK_DATA)(base + imp->OriginalFirstThunk);
			auto *iat = (PIMAGE_THUNK_DATA)(base + imp->FirstThunk);
			for (; names->u1.AddressOfData; names++, iat++) {
				// Ordinals are not guaranteed to match between emulator and real DLL.
				if (IMAGE_SNAP_BY_ORDINAL(names->u1.Ordinal))
					continue;
				auto *byName = (PIMAGE_IMPORT_BY_NAME)(base + names->u1.AddressOfData);
				void *target = (void *)GetProcAddress(hEmulator, byName->Name);
				if (!target || (void *)iat->u1.Function == target)
					continue;

				DWORD oldProt;
				if (!VirtualProtect(&iat->u1.Function, sizeof(iat->u1.Function), PAGE_READWRITE, &oldProt))
					continue;
				iat->u1.Function = (ULONG_PTR)target;
				VirtualProtect(&iat->u1.Function, sizeof(iat->u1.Function), oldProt, &oldProt);
				++rebound;
			}
		}
	}
	return rebound;
}

// rebindImports only when the emulator was loaded before us: on the LdrLoadDll
// path it was just loaded, so nothing can have bound to it yet.
static void SetupSteamApiForwarding(HMODULE hEmulator, bool rebindImports) {
	if (!hEmulator || InterlockedCompareExchange(&s_api_forward_state, 1, 0) != 0)
		return;

	WCHAR realPath[MAX_PATH]{};
	GetModuleFileNameW(hEmulator, realPath, MAX_PATH);
	LOG("[DSE-DLL] steam_api64.dll emulator at %p: %ls\n", hEmulator, realPath);
	PathRemoveFileSpecW(realPath);
	if (!PathAppendW(realPath, L"steam_api64_o.dll") ||
		GetFileAttributesW(realPath) == INVALID_FILE_ATTRIBUTES) {
		LOG("[DSE-DLL] steam_api64_o.dll not found next to the emulator: %ls\n", realPath);
		InterlockedExchange(&s_api_forward_state, 0);
		return;
	}

	HMODULE hReal = LoadLibraryExW(realPath, nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
	if (!hReal) {
		LOG("[DSE-DLL] Failed to load %ls: %lu\n", realPath, GetLastError());
		InterlockedExchange(&s_api_forward_state, 0);
		return;
	}
	LOG("[DSE-DLL] Real steam_api64 loaded at %p from %ls\n", hReal, realPath);

	const int forwarded = HookAllExports(hEmulator, hReal);

	// Hooks retarget the emulator's trampolines, so they go in before the IATs
	// are pointed at those trampolines.
	if (forwarded > 0 && g_config.steamHooks)
		HookSteamAPI(hEmulator);

	const int rebound = rebindImports ? RebindImports("steam_api64.dll", hEmulator) : 0;
	LOG("[DSE-DLL] steam_api64: %d exports forwarded, %d IAT entries rebound\n", forwarded, rebound);

	HideLdrEntry(hReal);
	InterlockedExchange(&s_api_forward_state, forwarded > 0 ? 2 : 0);
}

static bool IsSteamApi64Module(HMODULE hModule) {
	WCHAR path[MAX_PATH]{};
	return GetModuleFileNameW(hModule, path, MAX_PATH) &&
		   _wcsicmp(PathFindFileNameW(path), L"steam_api64.dll") == 0;
}

// Hooked at LdrLoadDll so it never collides with the LoadLibrary* detours in
// steam_hooks.cpp / steam_coldclient_hooks.cpp. Data-file loads never get here.
typedef NTSTATUS(NTAPI *fnLdrLoadDll)(PWSTR, PULONG, PVOID, PVOID *);
static fnLdrLoadDll oLdrLoadDll = nullptr;

static NTSTATUS NTAPI hkLdrLoadDll(PWSTR searchPath, PULONG characteristics, PVOID dllName,
								   PVOID *dllHandle) {
	NTSTATUS status = oLdrLoadDll(searchPath, characteristics, dllName, dllHandle);
	if (status >= 0 && dllHandle && *dllHandle &&
		InterlockedCompareExchange(&s_api_forward_state, 0, 0) == 0 &&
		IsSteamApi64Module((HMODULE)*dllHandle))
		SetupSteamApiForwarding((HMODULE)*dllHandle, false);
	return status;
}

void InitSteamApiForward() {
	HMODULE hExisting = GetModuleHandleW(L"steam_api64.dll");
	if (hExisting) {
		LOG("[DSE-DLL] steam_api64.dll already in memory at %p - setting up forwarding\n", hExisting);
		SetupSteamApiForwarding(hExisting, true);
		if (s_api_forward_state == 2)
			return;
	}

	void *pLdrLoadDll = (void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "LdrLoadDll");
	if (pLdrLoadDll && MH_CreateHook(pLdrLoadDll, (void *)hkLdrLoadDll, (void **)&oLdrLoadDll) == MH_OK &&
		MH_EnableHook(pLdrLoadDll) == MH_OK)
		LOG("[DSE-DLL] Hooked LdrLoadDll to intercept steam_api64.dll\n");
	else
		LOG("[DSE-DLL] Failed to hook LdrLoadDll for steam_api64 forwarding\n");
}
