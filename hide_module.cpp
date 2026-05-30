#include "peb_struct.h"
#include "log.h"
#include <cwchar>
#include <shlwapi.h>
#include <stdio.h>
#include <windows.h>
#include <winnt.h>
#include <winternl.h>

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

	// remove from InLoadOrderModuleList
	_LIST_ENTRY *pNode = pPEB->Ldr->InLoadOrderModuleList.Flink;
	while (true) {
		if (pNode == &pPEB->Ldr->InLoadOrderModuleList) {
			LOG("[DSE-DLL] Module not found in InLoadOrderModuleList!\n");
			break;
		}

		_LDR_DATA_TABLE_ENTRY_CUSTOM *dataEntry = CONTAINING_RECORD(pNode, LDR_DATA_TABLE_ENTRY_CUSTOM, InLoadOrderLinks);

		if (dataEntry->DllBase == hModule) {
			LOG("[DSE-DLL] Found module in InLoadOrderModuleList, removing it...\n");
			dataEntry->HashLinks.Blink->Flink = dataEntry->HashLinks.Flink;
			dataEntry->HashLinks.Flink->Blink = dataEntry->HashLinks.Blink;

			dataEntry->InLoadOrderLinks.Blink->Flink = (PLIST_ENTRY)dataEntry->InLoadOrderLinks.Flink;
			dataEntry->InLoadOrderLinks.Flink->Blink = (PLIST_ENTRY)dataEntry->InLoadOrderLinks.Blink;
			break;
		}

		pNode = dataEntry->InLoadOrderLinks.Flink;
	}

	// remove from InitializationOrderModuleList
	pNode = pPEB->Ldr->InInitializationOrderModuleList.Flink;

	while (true) {
		if (pNode == &pPEB->Ldr->InInitializationOrderModuleList) {
			LOG("[DSE-DLL] Module not found in InInitializationOrderModuleList!\n");
			break;
		}

		_LDR_DATA_TABLE_ENTRY_CUSTOM *dataEntry = CONTAINING_RECORD(pNode, LDR_DATA_TABLE_ENTRY_CUSTOM, InInitializationOrderLinks);

		if (dataEntry->DllBase == hModule) {
			LOG("[DSE-DLL] Found module in InInitializationOrderModuleList, removing it...\n");
			dataEntry->HashLinks.Blink->Flink = dataEntry->HashLinks.Flink;
			dataEntry->HashLinks.Flink->Blink = dataEntry->HashLinks.Blink;

			dataEntry->InInitializationOrderLinks.Blink->Flink = (PLIST_ENTRY)dataEntry->InInitializationOrderLinks.Flink;
			dataEntry->InInitializationOrderLinks.Flink->Blink = (PLIST_ENTRY)dataEntry->InInitializationOrderLinks.Blink;
			break;
		}

		pNode = dataEntry->InInitializationOrderLinks.Flink;
	}

	// remove from InMemoryOrderModuleList
	pNode = pPEB->Ldr->InMemoryOrderModuleList.Flink;

	while (true) {
		if (pNode == &pPEB->Ldr->InMemoryOrderModuleList) {
			LOG("[DSE-DLL] Module not found in InMemoryOrderModuleList!\n");
			break;
		}
		
		_LDR_DATA_TABLE_ENTRY_CUSTOM *dataEntry = CONTAINING_RECORD(pNode, LDR_DATA_TABLE_ENTRY_CUSTOM, InMemoryOrderLinks);

		if (dataEntry->DllBase == hModule) {
			LOG("[DSE-DLL] Found module in InMemoryOrderModuleList, removing it...\n");
			dataEntry->HashLinks.Blink->Flink = dataEntry->HashLinks.Flink;
			dataEntry->HashLinks.Flink->Blink = dataEntry->HashLinks.Blink;

			dataEntry->InMemoryOrderLinks.Blink->Flink = (PLIST_ENTRY)dataEntry->InMemoryOrderLinks.Flink;
			dataEntry->InMemoryOrderLinks.Flink->Blink = (PLIST_ENTRY)dataEntry->InMemoryOrderLinks.Blink;
			break;
		}

		pNode = dataEntry->InMemoryOrderLinks.Flink;
	}

	return 0;
}