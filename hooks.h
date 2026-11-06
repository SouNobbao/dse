#pragma once
// Central hooking toolkit: every low-level hook mechanism lives here so the
// steam_*.cpp files carry only their detours and dispatch. Covers MinHook
// install wrappers, safe cross-module memory access, vtable swaps (generic +
// ISteamClient), EAT export forwarding, and IAT rebinding. This header is
// textually included into the single dllmain translation unit, so everything
// stays 'static' (one TU) and must appear before its first use.

#include "log.h"
#include "minhook/include/MinHook.h"
#include "peb_struct.h"
#include <cstdint>
#include <cstring>
#include <shlwapi.h>
#include <windows.h>

// ---------------------------------------------------------------------------
// MinHook install wrappers (create only; callers enable per-target or in bulk).
// ---------------------------------------------------------------------------
static bool HookApi(LPCWSTR mod, LPCSTR name, LPVOID detour, LPVOID *orig) {
	LPVOID target = nullptr;
	if (MH_CreateHookApiEx(mod, name, detour, orig, &target) != MH_OK) {
		LOG("[DSE-DLL] Hook create failed: %ls!%hs\n", mod, name);
		return false;
	}
	if (MH_EnableHook(target) != MH_OK) {
		LOG("[DSE-DLL] Hook enable failed: %ls!%hs\n", mod, name);
		return false;
	}
	return true;
}

static bool Hook(LPVOID target, LPVOID detour, LPVOID *orig) {
	if (MH_CreateHook(target, detour, orig) != MH_OK) {
		LOG("[DSE-DLL] Hook create failed at %p\n", target);
		return false;
	}
	if (MH_EnableHook(target) != MH_OK) {
		LOG("[DSE-DLL] Hook enable failed at %p\n", target);
		return false;
	}
	return true;
}

// ---------------------------------------------------------------------------
// Safe cross-module memory access (vtable/export surgery touches foreign pages).
// ---------------------------------------------------------------------------
static bool IsAccessibleRange(const void *address, size_t size, bool writeAccess) {
	if (!address || size == 0)
		return false;

	uintptr_t current = reinterpret_cast<uintptr_t>(address);
	if (current + size < current)
		return false;
	const uintptr_t end = current + size;

	while (current < end) {
		MEMORY_BASIC_INFORMATION mbi{};
		if (VirtualQuery(reinterpret_cast<const void *>(current), &mbi, sizeof(mbi)) != sizeof(mbi) ||
			mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
			return false;

		const DWORD protection = mbi.Protect & 0xff;
		const bool readable = protection == PAGE_READONLY || protection == PAGE_READWRITE ||
							  protection == PAGE_WRITECOPY || protection == PAGE_EXECUTE_READ ||
							  protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY;
		const bool writable = protection == PAGE_READWRITE || protection == PAGE_WRITECOPY ||
							  protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY;
		if (!readable || (writeAccess && !writable))
			return false;

		const uintptr_t regionEnd = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
		if (regionEnd <= current)
			return false;
		current = regionEnd < end ? regionEnd : end;
	}
	return true;
}

template <typename T>
static bool TryReadValue(const T *source, T *destination) {
	if (!source || !destination)
		return false;
#if defined(_MSC_VER) && !defined(__clang__)
	__try {
		*destination = *source;
		return true;
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		return false;
	}
#else
	if (!IsAccessibleRange(source, sizeof(T), false))
		return false;
	*destination = *source;
	return true;
#endif
}

template <typename T>
static bool TryWriteValue(T *destination, const T &value) {
	if (!destination)
		return false;
#if defined(_MSC_VER) && !defined(__clang__)
	__try {
		*destination = value;
		return true;
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		return false;
	}
#else
	if (!IsAccessibleRange(destination, sizeof(T), true))
		return false;
	*destination = value;
	return true;
#endif
}

// ---------------------------------------------------------------------------
// Generic vtable swap: clone an object's vtable, patch slots, swap the pointer.
// ---------------------------------------------------------------------------
enum {
	kMaxGenericVTableSlots = 120,
	kMaxGenericVTableSwaps = 64
};

struct GenericVTableSwap {
	void *object;
	void **realVTable;
	void **fakeVTable;
	size_t numSlots;
	void *storage[kMaxGenericVTableSlots + 2];
};

static SRWLOCK g_vtableSwapLock = SRWLOCK_INIT;
static GenericVTableSwap g_GenericVTableSwaps[kMaxGenericVTableSwaps]{};

static GenericVTableSwap *FindGenericSwapByObjectLocked(void *object) {
	for (int i = 0; i < kMaxGenericVTableSwaps; i++) {
		if (g_GenericVTableSwaps[i].object == object)
			return &g_GenericVTableSwaps[i];
	}
	return nullptr;
}

static GenericVTableSwap *FindGenericSwapByFakeVTableLocked(void **vtable) {
	for (int i = 0; i < kMaxGenericVTableSwaps; i++) {
		if (g_GenericVTableSwaps[i].fakeVTable == vtable)
			return &g_GenericVTableSwaps[i];
	}
	return nullptr;
}

static GenericVTableSwap *BeginGenericVTableSwapLocked(void *pInterface, size_t numSlots,
													   bool *freshSwap) {
	if (freshSwap)
		*freshSwap = false;
	if (!pInterface)
		return nullptr;

	AcquireSRWLockExclusive(&g_vtableSwapLock);

	void **vtable = nullptr;
	if (!TryReadValue(reinterpret_cast<void ***>(pInterface), &vtable)) {
		ReleaseSRWLockExclusive(&g_vtableSwapLock);
		return nullptr;
	}

	GenericVTableSwap *existing = FindGenericSwapByObjectLocked(pInterface);
	if (!existing)
		existing = FindGenericSwapByFakeVTableLocked(vtable);
	if (existing) {
		ReleaseSRWLockExclusive(&g_vtableSwapLock);
		return existing;
	}

	GenericVTableSwap *slot = nullptr;
	for (int i = 0; i < kMaxGenericVTableSwaps; i++) {
		if (!g_GenericVTableSwaps[i].object) {
			slot = &g_GenericVTableSwaps[i];
			break;
		}
	}
	if (!slot) {
		ReleaseSRWLockExclusive(&g_vtableSwapLock);
		LOG("[DSE-DLL] No free vtable swap slots for object %p\n", pInterface);
		return nullptr;
	}

	if (numSlots > kMaxGenericVTableSlots)
		numSlots = kMaxGenericVTableSlots;

	void **fakeVTable = (void **)&slot->storage[2];
	TryReadValue(vtable - 2, fakeVTable - 2);
	TryReadValue(vtable - 1, fakeVTable - 1);

	for (size_t i = 0; i < numSlots; i++) {
		if (!TryReadValue(vtable + i, fakeVTable + i)) {
			numSlots = i;
			break;
		}
	}

	slot->object = pInterface;
	slot->realVTable = vtable;
	slot->fakeVTable = fakeVTable;
	slot->numSlots = numSlots;
	if (freshSwap)
		*freshSwap = true;
	return slot;
}

static void AbortGenericVTableSwapLocked(GenericVTableSwap *swap) {
	if (swap) {
		swap->object = nullptr;
		swap->realVTable = nullptr;
		swap->fakeVTable = nullptr;
		swap->numSlots = 0;
	}
	ReleaseSRWLockExclusive(&g_vtableSwapLock);
}

static bool PublishGenericVTableSwapLocked(GenericVTableSwap *swap) {
	if (!swap || !swap->object || !swap->fakeVTable) {
		ReleaseSRWLockExclusive(&g_vtableSwapLock);
		return false;
	}

	DWORD oldProtect = 0;
	if (!VirtualProtect(swap->object, sizeof(void *), PAGE_READWRITE, &oldProtect)) {
		LOG("[DSE-DLL] Failed to swap vtable for object %p: %lu\n", swap->object, GetLastError());
		AbortGenericVTableSwapLocked(swap);
		return false;
	}
	MemoryBarrier();
	*(void ***)swap->object = swap->fakeVTable;
	VirtualProtect(swap->object, sizeof(void *), oldProtect, &oldProtect);
	LOG("[DSE-DLL] VTable swapped object at %p (real=%p fake=%p)\n",
		swap->object, swap->realVTable, swap->fakeVTable);
	ReleaseSRWLockExclusive(&g_vtableSwapLock);
	return true;
}

static void *GetGenericOriginalSlotForDetour(void *self, void *detour, void *fallback) {
	if (!self || !detour)
		return fallback;

	void *result = fallback;
	AcquireSRWLockShared(&g_vtableSwapLock);
	GenericVTableSwap *swap = FindGenericSwapByObjectLocked(self);
	if (!swap) {
		void **vtable = nullptr;
		TryReadValue(reinterpret_cast<void ***>(self), &vtable);
		if (vtable)
			swap = FindGenericSwapByFakeVTableLocked(vtable);
	}

	if (swap && swap->realVTable && swap->fakeVTable) {
		for (size_t i = 0; i < swap->numSlots; i++) {
			if (swap->fakeVTable[i] == detour) {
				result = swap->realVTable[i];
				break;
			}
		}
	}
	ReleaseSRWLockShared(&g_vtableSwapLock);
	return result;
}

// ---------------------------------------------------------------------------
// ISteamClient vtable swap: like the generic one, with a tracked callback slot.
// ---------------------------------------------------------------------------
enum {
	kMaxClientVTableSlots = 120,
	kMaxClientVTableSwaps = 16
};

struct ClientVTableSwap {
	void *object;
	void **realVTable;
	void **fakeVTable;
	size_t numSlots;
	int callbackSlot;
	void *storage[kMaxClientVTableSlots + 2];
};

static ClientVTableSwap g_ClientVTableSwaps[kMaxClientVTableSwaps]{};

static ClientVTableSwap *FindClientSwapByObjectLocked(void *object) {
	for (int i = 0; i < kMaxClientVTableSwaps; i++) {
		if (g_ClientVTableSwaps[i].object == object)
			return &g_ClientVTableSwaps[i];
	}
	return nullptr;
}

static ClientVTableSwap *FindClientSwapByFakeVTableLocked(void **vtable) {
	for (int i = 0; i < kMaxClientVTableSwaps; i++) {
		if (g_ClientVTableSwaps[i].fakeVTable == vtable)
			return &g_ClientVTableSwaps[i];
	}
	return nullptr;
}

static void *GetClientOriginalSlot(void *self, int slot, void *fallback) {
	if (self && slot >= 0 && slot < kMaxClientVTableSlots) {
		void *result = fallback;
		AcquireSRWLockShared(&g_vtableSwapLock);
		ClientVTableSwap *swap = FindClientSwapByObjectLocked(self);
		if (!swap) {
			void **vtable = nullptr;
			if (TryReadValue(reinterpret_cast<void ***>(self), &vtable))
				swap = FindClientSwapByFakeVTableLocked(vtable);
		}
		if (swap && swap->realVTable && (size_t)slot < swap->numSlots)
			result = swap->realVTable[slot];
		ReleaseSRWLockShared(&g_vtableSwapLock);
		return result;
	}
	return fallback;
}

static void *GetClientCallbackOriginal(void *self, void *fallback) {
	if (!self)
		return fallback;

	void *result = fallback;
	AcquireSRWLockShared(&g_vtableSwapLock);
	ClientVTableSwap *swap = FindClientSwapByObjectLocked(self);
	if (!swap) {
		void **vtable = nullptr;
		if (TryReadValue(reinterpret_cast<void ***>(self), &vtable))
			swap = FindClientSwapByFakeVTableLocked(vtable);
	}
	if (swap && swap->realVTable && swap->callbackSlot >= 0 &&
		(size_t)swap->callbackSlot < swap->numSlots) {
		result = swap->realVTable[swap->callbackSlot];
	}
	ReleaseSRWLockShared(&g_vtableSwapLock);
	return result;
}

static ClientVTableSwap *BeginClientVTableSwapLocked(void *pInterface, size_t numSlots,
													 bool *freshSwap) {
	if (freshSwap)
		*freshSwap = false;
	if (!pInterface)
		return nullptr;

	AcquireSRWLockExclusive(&g_vtableSwapLock);

	void **vtable = nullptr;
	if (!TryReadValue(reinterpret_cast<void ***>(pInterface), &vtable)) {
		ReleaseSRWLockExclusive(&g_vtableSwapLock);
		return nullptr;
	}

	ClientVTableSwap *existing = FindClientSwapByObjectLocked(pInterface);
	if (!existing)
		existing = FindClientSwapByFakeVTableLocked(vtable);
	if (existing) {
		ReleaseSRWLockExclusive(&g_vtableSwapLock);
		return existing;
	}

	ClientVTableSwap *slot = nullptr;
	for (int i = 0; i < kMaxClientVTableSwaps; i++) {
		if (!g_ClientVTableSwaps[i].object) {
			slot = &g_ClientVTableSwaps[i];
			break;
		}
	}
	if (!slot) {
		LOG("[DSE-DLL] No free ISteamClient vtable swap slots for object %p\n", pInterface);
		ReleaseSRWLockExclusive(&g_vtableSwapLock);
		return nullptr;
	}

	if (numSlots > kMaxClientVTableSlots)
		numSlots = kMaxClientVTableSlots;

	void **fakeVTable = (void **)&slot->storage[2];
	TryReadValue(vtable - 2, fakeVTable - 2);
	TryReadValue(vtable - 1, fakeVTable - 1);

	for (size_t i = 0; i < numSlots; i++) {
		if (!TryReadValue(vtable + i, fakeVTable + i)) {
			numSlots = i;
			break;
		}
	}

	slot->object = pInterface;
	slot->realVTable = vtable;
	slot->fakeVTable = fakeVTable;
	slot->numSlots = numSlots;
	slot->callbackSlot = -1;
	if (freshSwap)
		*freshSwap = true;
	return slot;
}

static void AbortClientVTableSwapLocked(ClientVTableSwap *swap) {
	if (swap) {
		swap->object = nullptr;
		swap->realVTable = nullptr;
		swap->fakeVTable = nullptr;
		swap->numSlots = 0;
		swap->callbackSlot = -1;
	}
	ReleaseSRWLockExclusive(&g_vtableSwapLock);
}

static bool PublishClientVTableSwapLocked(ClientVTableSwap *swap) {
	if (!swap || !swap->object || !swap->fakeVTable) {
		ReleaseSRWLockExclusive(&g_vtableSwapLock);
		return false;
	}

	DWORD oldProtect = 0;
	if (!VirtualProtect(swap->object, sizeof(void *), PAGE_READWRITE, &oldProtect)) {
		LOG("[DSE-DLL] Failed to swap ISteamClient vtable for object %p: %lu\n",
			swap->object, GetLastError());
		AbortClientVTableSwapLocked(swap);
		return false;
	}
	MemoryBarrier();
	*(void ***)swap->object = swap->fakeVTable;
	VirtualProtect(swap->object, sizeof(void *), oldProtect, &oldProtect);
	LOG("[DSE-DLL] ISteamClient vtable swapped object at %p (real=%p fake=%p)\n",
		swap->object, swap->realVTable, swap->fakeVTable);
	ReleaseSRWLockExclusive(&g_vtableSwapLock);
	return true;
}

// ---------------------------------------------------------------------------
// EAT forwarding: rewrite a module's export table to jump to another module.
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// IAT rebinding: repoint already-bound imports of `dllName` at the emulator.
// ---------------------------------------------------------------------------
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
