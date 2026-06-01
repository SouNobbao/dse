#define WIN32_LEAN_AND_MEAN
#include <shellapi.h>
#include <shlwapi.h>
#include <windows.h>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
	int argc = 0;
	LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	if (!argv || argc < 2) {
		if (argv)
			LocalFree(argv);
		return 1;
	}

	LPCWSTR targetExe = argv[1];
	LPCWSTR targetArgs = (argc > 2) ? argv[2] : L"";

	WCHAR workDir[MAX_PATH]{};
	lstrcpynW(workDir, targetExe, MAX_PATH);
	PathRemoveFileSpecW(workDir);

	SHELLEXECUTEINFOW sei = {sizeof(sei)};
	sei.fMask = 0;
	sei.lpVerb = L"runas";
	sei.lpFile = targetExe;
	sei.lpParameters = targetArgs;
	sei.lpDirectory = workDir;
	sei.nShow = SW_SHOWNORMAL;

	if (!ShellExecuteExW(&sei)) {
		LocalFree(argv);
		return 1;
	}

	LocalFree(argv);
	return 0;
}
