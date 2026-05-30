#include "drvloader.h"

#include "common.h"
#include "drvloader_bin.cpp"
#include "log.h"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <processthreadsapi.h>
#include <shlwapi.h>
#include <winnt.h>

#pragma comment(lib, "shlwapi.lib")

WCHAR drvPath[MAX_PATH]{};

static BOOL WINAPI CallCreateProcessW(
	LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta,
	BOOL inherit, DWORD flags, LPVOID env, LPCWSTR cwd, LPSTARTUPINFOW si,
	LPPROCESS_INFORMATION pi) {
	LOG("[DSE-DLL] CreateProcessW -> %ls\n", cmd);
	if (OriginalCreateProcessW)
		return OriginalCreateProcessW(app, cmd, pa, ta, inherit, flags, env, cwd,
									  si, pi);
	return CreateProcessW(app, cmd, pa, ta, inherit, flags, env, cwd, si, pi);
}

bool IsRunningAsAdmin() {
	BOOL isAdmin = FALSE;
	PSID adminGroup = nullptr;
	SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
	if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
								 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
								 &adminGroup)) {
		CheckTokenMembership(nullptr, adminGroup, &isAdmin);
		FreeSid(adminGroup);
	}
	return isAdmin != FALSE;
}

void EnsureDrvExtracted() {
	if (drvPath[0] == L'\0') {
		GetTempPathW(MAX_PATH, drvPath);
		PathAppendW(drvPath, kDrvloaderExeName);
	}
	if (GetFileAttributesW(drvPath) == INVALID_FILE_ATTRIBUTES) {
		FILE *file = _wfopen(drvPath, L"wb");
		if (file) {
			size_t written = fwrite(drvloader_exe, 1, drvloader_exe_len, file);
			assert(written == drvloader_exe_len);
			fclose(file);
		}
	}
}

bool IsDseEnabled(bool defaultVal) {
	if (!IsRunningAsAdmin())
		return defaultVal;

	EnsureDrvExtracted();

	WCHAR workDir[MAX_PATH]{};
	GetTempPathW(MAX_PATH, workDir);

	SECURITY_ATTRIBUTES sa = {sizeof(sa), nullptr, TRUE};
	HANDLE hReadPipe = nullptr, hWritePipe = nullptr;
	if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0))
		return defaultVal;
	if (!SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0)) {
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);
		return defaultVal;
	}

	HANDLE hInRead = nullptr, hInWrite = nullptr;
	if (CreatePipe(&hInRead, &hInWrite, &sa, 0)) {
		SetHandleInformation(hInWrite, HANDLE_FLAG_INHERIT, 0);
		DWORD written = 0;
		WriteFile(hInWrite, "\n", 1, &written, nullptr);
		CloseHandle(hInWrite);
	}

	WCHAR cmdLine[MAX_PATH * 2]{};
	wsprintfW(cmdLine, L"\"%s\"", drvPath);

	STARTUPINFOW si = {sizeof(si)};
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdOutput = hWritePipe;
	si.hStdError = hWritePipe;
	si.hStdInput = hInRead;

	PROCESS_INFORMATION pi{};
	BOOL ok = CallCreateProcessW(nullptr, cmdLine, nullptr, nullptr, TRUE,
								 CREATE_NO_WINDOW, nullptr, workDir, &si, &pi);
	CloseHandle(hWritePipe);
	if (hInRead)
		CloseHandle(hInRead);

	if (!ok) {
		CloseHandle(hReadPipe);
		return defaultVal;
	}

	char buf[2048] = {};
	DWORD totalRead = 0;
	while (totalRead < sizeof(buf) - 1) {
		DWORD bytesRead = 0;
		if (!ReadFile(hReadPipe, buf + totalRead,
					  (DWORD)(sizeof(buf) - 1 - totalRead), &bytesRead, nullptr) ||
			bytesRead == 0)
			break;
		totalRead += bytesRead;
		buf[totalRead] = '\0';
		char *statusPtr = strstr(buf, "DSE Status:");
		if (statusPtr && strchr(statusPtr, '\n')) {
			TerminateProcess(pi.hProcess, 0);
			break;
		}
	}
	buf[totalRead] = '\0';
	CloseHandle(hReadPipe);

	WaitForSingleObject(pi.hProcess, 15000);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	bool disabled = strstr(buf, "DSE Status: PATCHED") != nullptr;
	LOG("[DSE-DLL] DSE status: %s\n", disabled ? "DISABLED" : "ENABLED");

	return !disabled;
}

void RunDrvCommand(LPCWSTR args) {
	EnsureDrvExtracted();

	if (!IsRunningAsAdmin()) {
		LOG("[DSE-DLL] Skipping drvloader command because process is not elevated\n");
		return;
	}

	WCHAR workDir[MAX_PATH]{};
	GetTempPathW(MAX_PATH, workDir);

	WCHAR cmdLine[MAX_PATH * 2]{};
	wsprintfW(cmdLine, L"\"%s\" %s", drvPath, args);
	LOG("[DSE-DLL] Running: %ls\n", cmdLine);

	SECURITY_ATTRIBUTES sa = {sizeof(sa), nullptr, TRUE};
	HANDLE hInRead = nullptr, hInWrite = nullptr;
	if (CreatePipe(&hInRead, &hInWrite, &sa, 0)) {
		SetHandleInformation(hInWrite, HANDLE_FLAG_INHERIT, 0);
		DWORD written = 0;
		WriteFile(hInWrite, "\n", 1, &written, nullptr);
		CloseHandle(hInWrite);
	}

	HANDLE hNul = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
							  &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

	STARTUPINFOW si = {sizeof(si)};
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = hInRead;
	si.hStdOutput = hNul;
	si.hStdError = hNul;

	PROCESS_INFORMATION pi{};
	if (CallCreateProcessW(nullptr, cmdLine, nullptr, nullptr, TRUE,
						   CREATE_NO_WINDOW, nullptr, workDir, &si, &pi)) {
		WaitForSingleObject(pi.hProcess, 15000);
		DWORD exitCode = 0;
		GetExitCodeProcess(pi.hProcess, &exitCode);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		LOG("[DSE-DLL] drvloader exited with code %lu\n", exitCode);
	} else {
		LOG("[DSE-DLL] CreateProcessW failed: %lu\n", GetLastError());
	}
	if (hInRead)
		CloseHandle(hInRead);
	if (hNul && hNul != INVALID_HANDLE_VALUE)
		CloseHandle(hNul);
}

void DisableDse() { RunDrvCommand(L"bypass"); }

void EnableDse() { RunDrvCommand(L"restore"); }

void DeleteDrvFile() { DeleteFileW(drvPath); }
