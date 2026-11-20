#include "SymbolDownloader.h"
#include <cstdio>
#include <string>

extern "C" __declspec(dllexport) void CALLBACK
DseDownloadPdb(HWND, HINSTANCE, LPSTR lpszCmdLine, int) {
	if (!lpszCmdLine || !lpszCmdLine[0]) {
		ExitProcess(1);
		return;
	}

	AttachConsole(ATTACH_PARENT_PROCESS);
	FILE *dummy;
	freopen_s(&dummy, "CONOUT$", "w", stdout);

	int len = MultiByteToWideChar(CP_ACP, 0, lpszCmdLine, -1, nullptr, 0);
	std::wstring modulePath(len - 1, 0);
	MultiByteToWideChar(CP_ACP, 0, lpszCmdLine, -1, &modulePath[0], len);

	SymbolDownloader sd;
	if (!sd.Initialize()) {
		ExitProcess(2);
		return;
	}
	bool ok = sd.DownloadPdb(modulePath);
	ExitProcess(ok ? 0 : 3);
}
