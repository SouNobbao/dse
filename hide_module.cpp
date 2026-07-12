#include "peb_struct.h"
#include "log.h"
#include <cwchar>
#include <shlwapi.h>
#include <stdio.h>
#include <windows.h>
#include <winnt.h>
#include <winternl.h>

void UnlinkModule(PLIST_ENTRY entry) {
	PLIST_ENTRY blink = entry->Blink;
	PLIST_ENTRY flink = entry->Flink;

	if (blink)
		blink->Flink = flink;
	if (flink)
		flink->Blink = blink;

	entry->Flink = entry;
	entry->Blink = entry;
}

int HideModule() {
	HMODULE hModule = NULL;
	GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
					   (LPCWSTR)&HideModule, &hModule);

	if (!hModule) {
		LOG("[DSE-DLL] GetModuleHandleExW failed!\n");
		return -1;
	}
	LOG("[DSE-DLL] Got module handle: %p\n", hModule);

	PEB_CUSTOM *pPEB = (PEB_CUSTOM *)__readgsqword(0x60);
	if (!pPEB || !pPEB->Ldr) {
		LOG("[DSE-DLL] PEB/Ldr unavailable!\n");
		return -1;
	}

	PPEB_LDR_DATA_CUSTOM ldr = pPEB->Ldr;

	LDR_DATA_TABLE_ENTRY_CUSTOM *self = NULL;
	for (PLIST_ENTRY node = ldr->InLoadOrderModuleList.Flink;
		 node != &ldr->InLoadOrderModuleList; node = node->Flink) {
		LDR_DATA_TABLE_ENTRY_CUSTOM *entry =
			CONTAINING_RECORD(node, LDR_DATA_TABLE_ENTRY_CUSTOM, InLoadOrderLinks);
		if (entry->DllBase == hModule) {
			self = entry;
			break;
		}
	}

	if (!self) {
		LOG("[DSE-DLL] Module not found in InLoadOrderModuleList!\n");
		return -1;
	}

	LOG("[DSE-DLL] Unlinking module from loader lists...\n");
	UnlinkModule(&self->InLoadOrderLinks);
	UnlinkModule(&self->InMemoryOrderLinks);
	UnlinkModule(&self->InInitializationOrderLinks);
	UnlinkModule(&self->HashLinks);

	LOG("[DSE-DLL] Module hidden successfully.\n");
	return 0;
}