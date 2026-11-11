#include "log.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

bool g_loggingEnabled = false;

static WCHAR g_logPath[MAX_PATH] = {0};

void InitLogPath(HMODULE hModule) {
	if (g_logPath[0] != L'\0')
		return;
	if (!hModule)
		return;

	WCHAR path[MAX_PATH]{};
	if (!GetModuleFileNameW(hModule, path, MAX_PATH))
		return;
	PathRemoveFileSpecW(path);
	PathAppendW(path, L"dse-dll.log");
	lstrcpynW(g_logPath, path, MAX_PATH);
}

static HANDLE g_logFile = INVALID_HANDLE_VALUE;
static void AppendLogLine(const char *line) {
	if (!line || !line[0])
		return;
	if (g_logPath[0] == L'\0')
		return;

	if (g_logFile == INVALID_HANDLE_VALUE) {
		g_logFile = CreateFileW(g_logPath, FILE_APPEND_DATA,
								FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
								OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (g_logFile == INVALID_HANDLE_VALUE)
			return;
	}

	SYSTEMTIME t;
	GetLocalTime(&t);
	char header[32];
	int headerLen = snprintf(header, sizeof(header), "[dse-dll] [%02d:%02d:%02d] ",
							 t.wHour, t.wMinute, t.wSecond);
	DWORD written = 0;
	WriteFile(g_logFile, header, static_cast<DWORD>(headerLen), &written, nullptr);
	WriteFile(g_logFile, line, static_cast<DWORD>(strlen(line)), &written, nullptr);
}

void CloseLog() {
	if (g_logFile != INVALID_HANDLE_VALUE) {
		CloseHandle(g_logFile);
		g_logFile = INVALID_HANDLE_VALUE;
	}
}

void Log(const char *fmt, ...) {
	if (!fmt)
		return;

	char buffer[2048]{};
	va_list args;
	va_start(args, fmt);
	vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, fmt, args);
	va_end(args);

	static bool s_hasLast = false;
	static char s_lastLine[sizeof(buffer)]{};

	if (s_hasLast && strcmp(buffer, s_lastLine) == 0)
		return;
	s_hasLast = true;
	strcpy_s(s_lastLine, sizeof(s_lastLine), buffer);

	printf("[dse-dll] %s", buffer);
	AppendLogLine(buffer);
}

void SetupLogConsole(HMODULE hModule) {
	if (!g_loggingEnabled)
		return;
	InitLogPath(hModule);
	AllocConsole();
	FILE *dummy;
	freopen_s(&dummy, "CONOUT$", "w", stdout);
	freopen_s(&dummy, "CONOUT$", "w", stderr);
	freopen_s(&dummy, "CONIN$", "r", stdin);
	Log("Console initialized.\n");
}
