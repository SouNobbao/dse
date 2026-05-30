#include "peb_struct.h"
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

	PEB_CUSTOM *pPEB = (PEB_CUSTOM *)__readgsqword(0x60);

	// remove from InLoadOrderModuleList
	_LIST_ENTRY *pNode = pPEB->Ldr->InLoadOrderModuleList.Flink;
	while (true) {
		_LDR_DATA_TABLE_ENTRY_CUSTOM *dataEntry = CONTAINING_RECORD(pNode, LDR_DATA_TABLE_ENTRY_CUSTOM, InLoadOrderLinks);

		if (dataEntry->DllBase == hModule) {
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
		_LDR_DATA_TABLE_ENTRY_CUSTOM *dataEntry = CONTAINING_RECORD(pNode, LDR_DATA_TABLE_ENTRY_CUSTOM, InInitializationOrderLinks);

		if (dataEntry->DllBase == hModule) {
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
		_LDR_DATA_TABLE_ENTRY_CUSTOM *dataEntry = CONTAINING_RECORD(pNode, LDR_DATA_TABLE_ENTRY_CUSTOM, InMemoryOrderLinks);

		if (dataEntry->DllBase == hModule) {
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