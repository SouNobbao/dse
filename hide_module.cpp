#include "peb_struct.h"
#include "log.h"
#include <cwchar>
#include <shlwapi.h>
#include <stdio.h>
#include <windows.h>
#include <winnt.h>
#include <winternl.h>

static void UnlinkModule(PLIST_ENTRY entry) {
	PLIST_ENTRY blink = entry->Blink;
	PLIST_ENTRY flink = entry->Flink;

	if (blink)
		blink->Flink = flink;
	if (flink)
		flink->Blink = blink;

	entry->Flink = entry;
	entry->Blink = entry;
}

void HideLdrEntry(HMODULE hModule) {
	PEB_CUSTOM *pPEB = (PEB_CUSTOM *)__readgsqword(0x60);
	if (!pPEB || !pPEB->Ldr)
		return;

	PPEB_LDR_DATA_CUSTOM ldr = pPEB->Ldr;

	LDR_DATA_TABLE_ENTRY_CUSTOM *self = NULL;
	for (PLIST_ENTRY node = ldr->InLoadOrderModuleList.Flink; node != &ldr->InLoadOrderModuleList; node = node->Flink) {
		LDR_DATA_TABLE_ENTRY_CUSTOM *entry =
			CONTAINING_RECORD(node, LDR_DATA_TABLE_ENTRY_CUSTOM, InLoadOrderLinks);
		if (entry->DllBase == (PVOID)hModule) {
			self = entry;
			break;
		}
	}

	if (!self)
		return;

	UnlinkModule(&self->InLoadOrderLinks);
	UnlinkModule(&self->InMemoryOrderLinks);
	UnlinkModule(&self->InInitializationOrderLinks);
	UnlinkModule(&self->HashLinks);

	LOG("[DSE-DLL] Hid LDR entry for %p\n", hModule);
}

int HideModule() {
	HMODULE hModule = NULL;
	GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
					   (LPCWSTR)&HideModule, &hModule);
	if (!hModule) {
		LOG("[DSE-DLL] GetModuleHandleExW failed!\n");
		return -1;
	}
	HideLdrEntry(hModule);
	return 0;
}
