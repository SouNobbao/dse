#include "patcher.h"

#include "common.h"
#include "afterburner.h"
#include "log.h"

#ifndef _STABLE
// KVC path: still uses the embedded binary + subprocess model
#include "kvc_bin.cpp"
#endif

#ifdef _STABLE
// drvloader integrated: direct function calls, no subprocess
#include "drvloader/DrvCore.h"
#include "drvloader/ConfigManager.h"
#include "drvloader/rtcore_resource.h"

static DrvLoader g_loader;
static bool g_loaderInitialized = false;

static bool EnsureLoaderInitialized() {
	if (g_loaderInitialized) return true;
	g_loader.embeddedResourceData = rtcore_resource_data;
	g_loader.embeddedResourceSize = rtcore_resource_data_len;
	if (!g_loader.Initialize()) {
		LOG("[DSE-DLL] DrvLoader initialization failed\n");
		return false;
	}
	g_loaderInitialized = true;
	return true;
}
#endif

#include <stdio.h>
#include <processthreadsapi.h>
#include <shlwapi.h>
#include <winnt.h>

#pragma comment(lib, "shlwapi.lib")

#ifndef _STABLE
// ============================================================================
// KVC subprocess helpers (unchanged)
// ============================================================================

static WCHAR patcherPath[MAX_PATH]{};

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
#endif

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

#ifndef _STABLE
void EnsurePatcherExtracted() {
	if (patcherPath[0] == L'\0') {
		GetDseTempPath(kPatcherName, patcherPath);
	}
	if (GetFileAttributesW(patcherPath) == INVALID_FILE_ATTRIBUTES) {
		FILE *file = nullptr;
		_wfopen_s(&file, patcherPath, L"wb");
		if (file) {
			size_t written = fwrite(bin_patcher, 1, bin_patcher_len, file);
			fclose(file);
		}
	}
}
#else
void EnsurePatcherExtracted() {
	// No-op: drvloader is integrated, nothing to extract.
}
#endif

bool IsDseEnabled(bool defaultVal) {
	bool afterburnerKilledByUs = false;
	if (IsAfterburnerRunning()) {
		KillAfterBurner();
		afterburnerKilledByUs = true;
	}

	if (!IsRunningAsAdmin()) {
		if (afterburnerKilledByUs) {
			bool oldState = WasAfterburnerRunning();
			SetAfterburnerRunningState(true);
			StartAfterburner();
			SetAfterburnerRunningState(oldState);
		}
		return defaultVal;
	}

#ifdef _STABLE
	// Fast path: registry already tracks whether we patched DSE
	bool disabled = ConfigManager::IsPatchedFromRegistry();
#else
	// KVC subprocess path (unchanged)
	EnsurePatcherExtracted();

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
	wsprintfW(cmdLine, L"\"%s\"", patcherPath);

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
			bytesRead == 0) {
			TerminateProcess(pi.hProcess, 0);
			break;
		}
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

	bool disabled = strstr(buf, "Driver signature enforcement: DISABLED") != nullptr;
#endif

	LOG("[DSE-DLL] DSE status: %s\n", disabled ? "DISABLED" : "ENABLED");

	if (afterburnerKilledByUs) {
		bool oldState = WasAfterburnerRunning();
		SetAfterburnerRunningState(true);
		StartAfterburner();
		SetAfterburnerRunningState(oldState);
	}

	return !disabled;
}

#ifndef _STABLE
// KVC subprocess helper
static void RunPatcherCommand(LPCWSTR args) {
	KillAfterBurner();
	EnsurePatcherExtracted();

	if (!IsRunningAsAdmin()) {
		LOG("[DSE-DLL] Skipping patcher command because process is not elevated\n");
		return;
	}

	WCHAR workDir[MAX_PATH]{};
	GetTempPathW(MAX_PATH, workDir);

	WCHAR cmdLine[MAX_PATH * 2]{};
	wsprintfW(cmdLine, L"\"%s\" %s", patcherPath, args);
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
		LOG("[DSE-DLL] patcher exited with code %lu\n", exitCode);
	} else {
		LOG("[DSE-DLL] CreateProcessW failed: %lu\n", GetLastError());
	}
	if (hInRead)
		CloseHandle(hInRead);
	if (hNul && hNul != INVALID_HANDLE_VALUE)
		CloseHandle(hNul);
}
#endif

void DisableDse() {
#ifdef _STABLE
	KillAfterBurner();
	if (!IsRunningAsAdmin()) {
		LOG("[DSE-DLL] Skipping DSE disable because process is not elevated\n");
		return;
	}
	if (!EnsureLoaderInitialized()) return;
	if (!g_loader.BypassDSE()) {
		LOG("[DSE-DLL] DrvLoader.BypassDSE failed\n");
	}
#else
	RunPatcherCommand(patcherDisablearg);
#endif
}

void EnableDse() {
#ifdef _STABLE
	KillAfterBurner();
	if (!IsRunningAsAdmin()) {
		LOG("[DSE-DLL] Skipping DSE enable because process is not elevated\n");
		if (WasAfterburnerRunning()) StartAfterburner();
		return;
	}
	if (!EnsureLoaderInitialized()) {
		if (WasAfterburnerRunning()) StartAfterburner();
		return;
	}
	if (!g_loader.RestoreDSE()) {
		LOG("[DSE-DLL] DrvLoader.RestoreDSE failed\n");
	}
	if (WasAfterburnerRunning()) {
		StartAfterburner();
	}
#else
	RunPatcherCommand(patcherEnablearg);
	if (WasAfterburnerRunning()) {
		StartAfterburner();
	}
#endif
}

void DeletePatcherFile() {
#ifndef _STABLE
	DeleteFileW(patcherPath);
#endif
	// _STABLE: nothing to delete, no temp file extracted
}
