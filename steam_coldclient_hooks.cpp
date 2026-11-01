#pragma once
#include "config.h"
#include "log.h"
#include "minhook/include/MinHook.h"
#include "peb_struct.h"
#include <shlwapi.h>
#include <strsafe.h>
#include <windows.h>

// Interface hooking lives in steam_hooks.cpp. This file forwards the emulator's
// exports to the real client and hooks the real client's interfaces at load
// time; it keeps no code of its own in the forwarding path.
static void HookInterface_ISteamClient(void *pInterface, const char *pszVersion);
static void LoadSteamConfigFromDll(HMODULE hSteamApi);

// Unlink a module from the PEB's loader lists so it stops showing up in module
// walks. Called on the real client once its exports have been forwarded, so the
// emulator stays the only steamclient64 anyone can find by name.
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

// One trampoline is 14 bytes:
//
//     FF 25 00 00 00 00  <8-byte absolute target>     jmp qword ptr [rip+0]
//
// The zero displacement is intentional: the 8-byte target that follows is the
// absolute address, so the jump lands on it. 14 bytes keeps it 8-byte aligned,
// which matters because the target is stored inline.
static constexpr size_t kTrampolineSize = 14;

// Point one export-table entry at a trampoline, and write the trampoline.
//
// Returns the new RVA for the entry, or 0 if the trampoline cannot be addressed
// as an RVA of hSource. An export-table entry is a 32-bit RVA relative to the
// module base, so the trampoline has to sit within 4GB above that base; that is
// why they are allocated high rather than anywhere convenient.
static DWORD SetExportToTrampoline(DWORD *entryRva, HMODULE hSource, BYTE *trampoline,
								   void *target) {
	const uintptr_t source = reinterpret_cast<uintptr_t>(hSource);
	const uintptr_t address = reinterpret_cast<uintptr_t>(trampoline);
	if (address < source)
		return 0;

	const uintptr_t delta = address - source;
	// The whole trampoline must fit inside the remaining 32-bit RVA space, not
	// just its first byte.
	if (delta > 0xFFFFFFFFull || kTrampolineSize > 0x100000000ull - delta)
		return 0;

	trampoline[0] = 0xFF;
	trampoline[1] = 0x25;
	trampoline[2] = 0x00;
	trampoline[3] = 0x00;
	trampoline[4] = 0x00;
	trampoline[5] = 0x00;
	memcpy(trampoline + 6, &target, sizeof(target));

	const DWORD newRva = static_cast<DWORD>(delta);
	*entryRva = newRva;
	return newRva;
}

// Rewrite every export of `hSource` to forward to the same-named export of
// `hTarget`.
//
// Nothing of ours ends up reachable through the emulator: each entry points at a
// trampoline whose target is the real client. Anything that cannot be forwarded
// is left exactly as it was, and reported.
//
// Returns the number of exports forwarded.
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

	WCHAR targetPath[MAX_PATH]{};
	GetModuleFileNameW(hTarget, targetPath, MAX_PATH);
	char targetName[MAX_PATH]{};
	WideCharToMultiByte(CP_ACP, 0, PathFindFileNameW(targetPath), -1, targetName, MAX_PATH, nullptr, nullptr);

	int forwarded = 0, skipped = 0, failed = 0;

	const size_t trampolineBytes = expDir->NumberOfNames * kTrampolineSize;
	BYTE *trampolineBase = (BYTE *)AllocateEatTrampolines(hSource, trampolineBytes,
														  nt->OptionalHeader.SizeOfImage);
	BYTE *trampoline = trampolineBase;
	if (!trampoline) {
		LOG("[DSE-DLL] Failed to allocate EAT trampolines above source module base!\n");
		return 0;
	}
	LOG("[DSE-DLL] EAT trampolines allocated at %p (source=%p, rva=0x%llX)\n", trampoline,
		hSource, (unsigned long long)((uintptr_t)trampoline - (uintptr_t)hSource));

	DWORD oldProt;
	if (!VirtualProtect(funcs, expDir->NumberOfFunctions * sizeof(DWORD), PAGE_READWRITE, &oldProt)) {
		LOG("[DSE-DLL] VirtualProtect on EAT failed: %lu\n", GetLastError());
		VirtualFree(trampolineBase, 0, MEM_RELEASE);
		return 0;
	}
	for (DWORD i = 0; i < expDir->NumberOfNames; i++) {
		const char *name = (const char *)((BYTE *)hSource + names[i]);

		// Already a forwarder string (module.export), so it already resolves
		// against whatever it names rather than to code in this image.
		const DWORD rva = funcs[ords[i]];
		if (rva >= expEntry.VirtualAddress && rva < expEntry.VirtualAddress + expEntry.Size)
			continue;

		// The real client is the only destination: forward to it, or leave the
		// emulator's own entry in place. There is deliberately no hook here, so
		// the game resolves every export straight to real steamclient64.
		void *target = (void *)GetProcAddress(hTarget, name);
		if (!target) {
			LOG("[DSE-DLL] %s stays on the emulator: not exported by the real %s\n",
				name, targetName);
			++skipped;
			continue;
		}

		if (!SetExportToTrampoline(&funcs[ords[i]], hSource, trampoline, target)) {
			LOG("[DSE-DLL] Failed to forward export %s: trampoline %p is not encodable as an EAT RVA\n",
				name, trampoline);
			++failed;
		} else {
			++forwarded;
		}

		// Consumed either way: a failed slot still advanced, so each export gets
		// its own trampoline and never shares one.
		trampoline += kTrampolineSize;
	}

	VirtualProtect(funcs, expDir->NumberOfFunctions * sizeof(DWORD), oldProt, &oldProt);
	DWORD trampOldProt = 0;
	FlushInstructionCache(GetCurrentProcess(), trampolineBase, trampolineBytes);
	if (!VirtualProtect(trampolineBase, trampolineBytes, PAGE_EXECUTE_READ, &trampOldProt)) {
		LOG("[DSE-DLL] Failed to set EAT trampolines RX: %lu\n", GetLastError());
	}

	LOG("[DSE-DLL] Export forwarding: %d forwarded, %d left on the emulator, %d failed\n",
		forwarded, skipped, failed);
	return forwarded;
}

typedef HMODULE(WINAPI *fnLoadLibraryExW)(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
static fnLoadLibraryExW oLoadLibraryExW = nullptr;

static volatile LONG s_steam_hook_state = 0; // 0 = not started, 1 = in progress, 2 = ready

// Obtain the real client's own interfaces and hook them.
//
// Resolved straight out of the real module, never through the emulator, so this
// adds nothing to the forwarding path: the emulator's export table still points
// only at real steamclient64.
//
// Returns the number of client interfaces hooked.
static int HookRealClientInterfaces(HMODULE hReal) {
	if (!hReal)
		return 0;

	typedef void *(*tCreateInterface)(const char *pName, int *pReturnCode);
	tCreateInterface realCreateInterface =
		reinterpret_cast<tCreateInterface>((void *)GetProcAddress(hReal, "CreateInterface"));
	if (!realCreateInterface) {
		LOG("[DSE-DLL] Real client exports no CreateInterface; interfaces left unhooked\n");
		return 0;
	}

	// Steam keeps one client object per version, and the game may ask for any of
	// them, so hook every one it offers rather than guessing which it wants.
	static const char *const kClientVersions[] = {"SteamClient021", "SteamClient020",
												  "SteamClient019", "SteamClient018",
												  "SteamClient017", "SteamClient016",
												  "SteamClient015", "SteamClient014",
												  nullptr};

	int hooked = 0;
	for (int i = 0; kClientVersions[i]; ++i) {
		int code = 0;
		void *client = realCreateInterface(kClientVersions[i], &code);
		if (!client)
			continue;
		LOG("[DSE-DLL] Pre-hooking real ISteamClient via %s @ %p\n", kClientVersions[i],
			client);
		HookInterface_ISteamClient(client, kClientVersions[i]);
		++hooked;
	}

	if (hooked == 0)
		LOG("[DSE-DLL] Real client returned no ISteamClient; interfaces left unhooked\n");
	return hooked;
}

// Make sure a second name exists for the real client inside the Steam
// directory, so it can be loaded as a distinct module from the emulator.
//
// Writes the alias path to `aliasPath` and sets `*outAliasCreated` when this call
// is what brought the alias into existence, so the caller can schedule its
// removal afterwards.
static bool PrepareRealClientAlias(const WCHAR *steamDir, const WCHAR *realPath,
								   WCHAR *aliasPath, bool *outAliasCreated) {
	*outAliasCreated = false;

	WCHAR aliasName[64]{};
	if (FAILED(StringCchPrintfW(aliasName, ARRAYSIZE(aliasName),
								L"steamclient64_valve.dll"))) {
		LOG("[DSE-DLL] Failed to build real Steam DLL alias name\n");
		return false;
	}
	if (!PathCombineW(aliasPath, steamDir, aliasName)) {
		LOG("[DSE-DLL] Real Steam DLL alias path is too long\n");
		return false;
	}

	if (GetFileAttributesW(aliasPath) != INVALID_FILE_ATTRIBUTES) {
		LOG("[DSE-DLL] Reusing existing real Steam DLL alias: %ls\n", aliasPath);
		return true;
	}

	// Hard link when the volume allows it, copy when it does not.
	if (!CreateHardLinkW(aliasPath, realPath, NULL)) {
		LOG("[DSE-DLL] Failed to create hard link for real Steam DLL: %lu\n",
			GetLastError());
		if (!CopyFileW(realPath, aliasPath, FALSE)) {
			LOG("[DSE-DLL] Fallback copy also failed: %lu\n", GetLastError());
			return false;
		}
	}
	*outAliasCreated = true;
	return true;
}

// Runs from inside the game's own LoadLibraryExW for steamclient64, before the
// game can call into it, so the interfaces are hooked before first use.
//
// At most one attempt runs at a time, gated by s_steam_hook_state. A failed
// attempt resets the state so a later load can retry.
static void SetupSteamClientForwarding(HMODULE hEmulator) {
	if (!hEmulator)
		return;
	if (InterlockedCompareExchange(&s_steam_hook_state, 1, 0) != 0)
		return;

	static const LPCWSTR kDllName = L"steamclient64.dll";
	g_hEmulatorClient = hEmulator;

	WCHAR loadedPath[MAX_PATH]{};
	GetModuleFileNameW(hEmulator, loadedPath, MAX_PATH);
	LOG("[DSE-DLL] %ls emulator loaded at %p\n", kDllName, hEmulator);
	LOG("[DSE-DLL] Steam emulator path: %ls\n", loadedPath);

	LoadSteamConfigFromDll(hEmulator);

	// Publishes the outcome and releases the state lock. Every failure below
	// funnels through here rather than through scattered early returns.
	auto finish = [](bool ok) {
		InterlockedExchange(&s_steam_hook_state, ok ? 2 : 0);
		if (!ok) {
			g_hRealSteamClient = nullptr;
			LOG("[DSE-DLL] Steam client forwarding setup did not complete; will retry on next load\n");
		}
	};

	const fnLoadLibraryExW loadLibraryExW = oLoadLibraryExW
												? oLoadLibraryExW
												: (fnLoadLibraryExW)&LoadLibraryExW;

	// Locates the real client, loads it under an alias name, forwards the
	// emulator's exports onto it, then hooks the real client's interfaces.
	auto setup = [&]() -> bool {
		WCHAR steamDir[MAX_PATH]{};
		if (!GetConfiguredSteamDir(steamDir, ARRAYSIZE(steamDir)))
			return false;

		WCHAR realPath[MAX_PATH]{};
		if (!PathCombineW(realPath, steamDir, kDllName)) {
			LOG("[DSE-DLL] Steam client path is too long\n");
			return false;
		}
		if (GetFileAttributesW(realPath) == INVALID_FILE_ATTRIBUTES) {
			LOG("[DSE-DLL] Steam %ls not found: %ls\n", kDllName, realPath);
			return false;
		}
		LOG("[DSE-DLL] Steam %ls: %ls\n", kDllName, realPath);

		WCHAR aliasPath[MAX_PATH]{};
		bool aliasCreated = false;
		if (!PrepareRealClientAlias(steamDir, realPath, aliasPath, &aliasCreated))
			return false;

		HMODULE hReal = loadLibraryExW(aliasPath, nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
		if (!hReal) {
			LOG("[DSE-DLL] Failed to load temp Steam DLL: %lu\n", GetLastError());
			return false;
		}
		LOG("[DSE-DLL] Steam loaded at %p from %ls\n", hReal, aliasPath);

		// Drop the alias once nothing holds it, so the Steam directory is left
		// the way we found it.
		if (aliasCreated && !MoveFileExW(aliasPath, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT))
			LOG("[DSE-DLL] Could not schedule Steam DLL alias cleanup: %lu\n",
				GetLastError());

		g_hRealSteamClient = hReal;

		const int forwarded = HookAllExports(hEmulator, hReal);
		if (forwarded > 0) {
			MH_EnableHook(MH_ALL_HOOKS);
			LOG("[DSE-DLL] %d emulator exports now forwarding to real %ls\n", forwarded,
				kDllName);
		} else {
			LOG("[DSE-DLL] No exports hooked for %ls!\n", kDllName);
		}

		// The emulator forwards everything to the real client, so the game talks
		// to real Steam objects with no code of ours in between. That also means
		// nothing is watching the interfaces it asks for, and it would read the
		// genuine SteamID straight out of ISteamUser.
		//
		// So the interfaces are hooked here, at load time, by asking the real
		// client for them ourselves. HookInterface_ISteamClient rewrites the
		// accessor slots of the real ISteamClient object, and those forwarders
		// are what let steam_hooks.cpp hook ISteamUser/ISteamApps as the game
		// obtains them.
		//
		// Resolved out of the real module, never through the emulator, so the
		// emulator's export table still points only at real steamclient64.
		HookRealClientInterfaces(hReal);

		HideLdrEntry(hReal);
		return forwarded > 0;
	};

	finish(setup());
}

static HMODULE WINAPI hkLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
	LPCWSTR targetPath = lpLibFileName;

	const bool isSteamClient = lpLibFileName && StrStrIW(lpLibFileName, L"steamclient64.dll");
	const bool isOverlay = lpLibFileName && StrStrIW(lpLibFileName, L"gameoverlayrenderer64.dll");

	// The overlay only runs when the game asks for it, so resolve it once and
	// cache the answer rather than rebuilding the path on every call.
	static bool s_overlay_hooked = false;
	static WCHAR overlayRealPath[MAX_PATH] = {0};

	if (isOverlay && !s_overlay_hooked) {
		if (overlayRealPath[0] == 0) {
			WCHAR steamDir[MAX_PATH]{};
			if (GetConfiguredSteamDir(steamDir, ARRAYSIZE(steamDir))) {
				if (!PathCombineW(overlayRealPath, steamDir, L"gameoverlayrenderer64.dll"))
					overlayRealPath[0] = L'\0';
			}
		}

		if (GetFileAttributesW(overlayRealPath) != INVALID_FILE_ATTRIBUTES) {
			targetPath = overlayRealPath;
			dwFlags |= LOAD_WITH_ALTERED_SEARCH_PATH;
			s_overlay_hooked = true;
			LOG("[DSE-DLL] Redirecting gameoverlayrenderer64.dll to valve : %ls\n", targetPath);
		}
	}

	HMODULE hModule = oLoadLibraryExW(targetPath, hFile, dwFlags);

	// Catch steamclient64 as it loads. This detour is the only thing of ours on
	// the game's load path: the emulator is a real module, not something we
	// synthesise, so it has to be observed here and hooked inside itself.
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
	if (proc || !hModule || hModule != g_hEmulatorClient || !g_hRealSteamClient)
		return proc;

	proc = oGetProcAddress(g_hRealSteamClient, lpProcName);
	if (proc && ((ULONG_PTR)lpProcName > 0xFFFF))
		LOG("[DSE-DLL] GetProcAddress forwarded %s to real steamclient\n", lpProcName);
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
