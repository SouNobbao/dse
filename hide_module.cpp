#include "peb_struct.h"
#include "log.h"
#include <windows.h>

void HideLdrEntry(HMODULE hModule) {
	PEB_CUSTOM *pPEB = (PEB_CUSTOM *)__readgsqword(0x60);
	if (!pPEB || !pPEB->Ldr)
		return;

	auto unlink = [&](_LIST_ENTRY *head, size_t linkOffset) {
		for (_LIST_ENTRY *p = head->Flink; p != head; p = p->Flink) {
			auto *entry = (_LDR_DATA_TABLE_ENTRY_CUSTOM *)((BYTE *)p - linkOffset);
			if (entry->DllBase == (PVOID)hModule) {
				_LIST_ENTRY *links = (_LIST_ENTRY *)((BYTE *)entry + linkOffset);
				links->Blink->Flink = links->Flink;
				links->Flink->Blink = links->Blink;
				return;
			}
		}
	};

	PPEB_LDR_DATA_CUSTOM ldr = pPEB->Ldr;

	// Unlink HashLinks first (walk InLoadOrder while it's still intact)
	for (_LIST_ENTRY *p = ldr->InLoadOrderModuleList.Flink; p != &ldr->InLoadOrderModuleList; p = p->Flink) {
		auto *entry = CONTAINING_RECORD(p, LDR_DATA_TABLE_ENTRY_CUSTOM, InLoadOrderLinks);
		if (entry->DllBase == (PVOID)hModule) {
			_LIST_ENTRY *h = &entry->HashLinks;
			h->Blink->Flink = h->Flink;
			h->Flink->Blink = h->Blink;
			break;
		}
	}

	unlink(&ldr->InLoadOrderModuleList, offsetof(LDR_DATA_TABLE_ENTRY_CUSTOM, InLoadOrderLinks));
	unlink(&ldr->InMemoryOrderModuleList, offsetof(LDR_DATA_TABLE_ENTRY_CUSTOM, InMemoryOrderLinks));
	unlink(&ldr->InInitializationOrderModuleList, offsetof(LDR_DATA_TABLE_ENTRY_CUSTOM, InInitializationOrderLinks));

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
