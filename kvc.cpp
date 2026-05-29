#include "kvc.h"

#include "common.h"
#include "config.h"
#include "kvc_bin.cpp"
#include "log.h"

#include <cassert>
#include <cstring>
#include <processthreadsapi.h>
#include <shlwapi.h>
#include <winnt.h>

#pragma comment(lib, "shlwapi.lib")

WCHAR kvcPath[MAX_PATH]{};

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

void EnsureKvcExtracted() {
	if (kvcPath[0] == L'\0') {
		GetTempPathW(MAX_PATH, kvcPath);
		PathAppendW(kvcPath, kKvcExeName);
	}
	if (GetFileAttributesW(kvcPath) == INVALID_FILE_ATTRIBUTES) {
		HANDLE hFile = CreateFileW(kvcPath, GENERIC_ALL, FILE_SHARE_READ, nullptr,
								   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (hFile != INVALID_HANDLE_VALUE) {
			DWORD written = 0;
			WriteFile(hFile, bin_kvc_exe, bin_kvc_exe_len, &written, nullptr);
			assert(written == sizeof(bin_kvc_exe));
			CloseHandle(hFile);
		}
	}
}

bool IsDseEnabled(bool defaultVal) {
	if (!IsRunningAsAdmin())
		return defaultVal;

	EnsureKvcExtracted();

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

	WCHAR cmdLine[MAX_PATH * 2]{};
	wsprintfW(cmdLine, L"\"%s\" dse", kvcPath);

	STARTUPINFOW si = {sizeof(si)};
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdOutput = hWritePipe;
	si.hStdError = hWritePipe;
	si.hStdInput = nullptr;

	PROCESS_INFORMATION pi{};
	BOOL ok = CallCreateProcessW(nullptr, cmdLine, nullptr, nullptr, TRUE,
								 CREATE_NO_WINDOW, nullptr, workDir, &si, &pi);
	CloseHandle(hWritePipe);

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
	}
	buf[totalRead] = '\0';
	WCHAR wbuf[2048]{};
	MultiByteToWideChar(CP_ACP, 0, buf, -1, wbuf, ARRAYSIZE(wbuf));
	LOG("[DSE-DLL] Buffer: %ls\n", wbuf);
	CloseHandle(hReadPipe);

	WaitForSingleObject(pi.hProcess, 15000);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	bool disabled =
		strstr(buf, "Driver signature enforcement: DISABLED") != nullptr;
	LOG("[DSE-DLL] DSE status: %s\n", disabled ? "DISABLED" : "ENABLED");
	DeleteKvcFile();
	return !disabled;
}

void RunKvcCommand(LPCWSTR args) {
	EnsureKvcExtracted();

	if (!IsRunningAsAdmin()) {
		LOG("[DSE-DLL] Skipping kvc command because process is not elevated\n");
		return;
	}

	WCHAR workDir[MAX_PATH]{};
	GetTempPathW(MAX_PATH, workDir);

	WCHAR cmdLine[MAX_PATH * 2]{};
	wsprintfW(cmdLine, L"\"%s\" %s", kvcPath, args);
	LOG("[DSE-DLL] Running: %ls\n", cmdLine);

	STARTUPINFOW si = {sizeof(si)};
	PROCESS_INFORMATION pi{};
	if (CallCreateProcessW(nullptr, cmdLine, nullptr, nullptr, FALSE,
						   CREATE_NO_WINDOW, nullptr, workDir, &si, &pi)) {
		WaitForSingleObject(pi.hProcess, 15000);
		DWORD exitCode = 0;
		GetExitCodeProcess(pi.hProcess, &exitCode);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		LOG("[DSE-DLL] kvc exited with code %lu\n", exitCode);
	} else {
		LOG("[DSE-DLL] CreateProcessW failed: %lu\n", GetLastError());
	}
	DeleteKvcFile();
}

void DisableDse() { RunKvcCommand(L"dse off"); }

void EnableDse() { RunKvcCommand(L"dse on"); }

void DeleteKvcFile() { DeleteFileW(kvcPath); }
