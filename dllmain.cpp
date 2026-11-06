#define WIN32_LEAN_AND_MEAN

#include "afterburner.h"
#include "common.h"
#include "config.h"
#include "events.h"
#include "hide_module.h"
#include "hooks.h"
#include "injector.h"
#include "launchers.h"
#include "log.h"
#include "minhook/include/MinHook.h"
#include "patcher.h"
#include "watchdog.h"

#include <shellapi.h>
#include <shlwapi.h>
#include <taskschd.h>
#include <windows.h>

#pragma comment(lib, "shlwapi.lib")

static WCHAR g_targetExe[MAX_PATH] = {0};
static bool g_wasOffFromStart = false;
static bool g_wasToggled = false;
static bool g_isLauncher = false;

extern "C" __declspec(dllexport) void DseDll(void) {}

// linker adds this causing more size
extern "C" char *__cxa_demangle(const char *, char *, size_t *, int *status) {
	if (status)
		*status = -1;
	return nullptr;
}

HMODULE g_hModule = nullptr;

#include "steam_hooks.cpp"
#include "steam_coldclient_hooks.cpp"
#include "steam_forward.cpp"

#include "checks.h"

#include "elevator_bin.cpp"

static bool RunPreRegisteredElevationTask(LPCWSTR selfExePath) {
	WCHAR taskName[MAX_PATH]{};
	lstrcpynW(taskName, L"dse_", ARRAYSIZE(taskName));
	WCHAR base[MAX_PATH]{};
	lstrcpynW(base, PathFindFileNameW(selfExePath), ARRAYSIZE(base));
	PathRemoveExtensionW(base);
	lstrcatW(taskName, base);

	HRESULT hrInit = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
	bool uninit = SUCCEEDED(hrInit);

	ITaskService *svc = nullptr;
	ITaskFolder *folder = nullptr;
	IRegisteredTask *task = nullptr;
	ITaskDefinition *def = nullptr;
	IPrincipal *principal = nullptr;
	IActionCollection *actions = nullptr;
	IAction *action = nullptr;
	IExecAction *exec = nullptr;
	BSTR bstr = nullptr;
	bool ran = false;

	VARIANT v;
	VariantInit(&v);

	if (FAILED(CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
								IID_ITaskService, (void **)&svc)))
		goto done;
	if (FAILED(svc->Connect(v, v, v, v)))
		goto done;

	bstr = SysAllocString(L"\\");
	if (FAILED(svc->GetFolder(bstr, &folder)))
		goto done;
	SysFreeString(bstr);
	bstr = nullptr;

	bstr = SysAllocString(taskName);
	if (FAILED(folder->GetTask(bstr, &task)) || !task) {
		LOG("[DSE-DLL] Elevation task '%ls' not registered.\n", taskName);
		goto done;
	}
	SysFreeString(bstr);
	bstr = nullptr;

	if (FAILED(task->get_Definition(&def)))
		goto done;

	// Refuse a task that isn't highest run level (fall back to UAC).
	if (FAILED(def->get_Principal(&principal)))
		goto done;
	{
		TASK_RUNLEVEL_TYPE rl = TASK_RUNLEVEL_LUA;
		if (FAILED(principal->get_RunLevel(&rl)) || rl != TASK_RUNLEVEL_HIGHEST) {
			LOG("[DSE-DLL] Elevation task '%ls' is not highest run level, ignoring.\n", taskName);
			goto done;
		}
	}

	// exactly one exec action, whose path is this exact exe.
	if (FAILED(def->get_Actions(&actions)))
		goto done;
	{
		LONG count = 0;
		if (FAILED(actions->get_Count(&count)) || count != 1) {
			LOG("[DSE-DLL] Elevation task '%ls' has %ld actions (want 1), ignoring.\n", taskName, count);
			goto done;
		}
	}
	if (FAILED(actions->get_Item(1, &action)))
		goto done;
	if (FAILED(action->QueryInterface(IID_IExecAction, (void **)&exec)))
		goto done;
	if (FAILED(exec->get_Path(&bstr)) || !bstr)
		goto done;
	if (_wcsicmp(bstr, selfExePath) != 0) {
		LOG("[DSE-DLL] Elevation task path mismatch ('%ls' != '%ls'), ignoring.\n", bstr, selfExePath);
		goto done;
	}
	SysFreeString(bstr);
	bstr = nullptr;

	{
		IRunningTask *running = nullptr;
		if (SUCCEEDED(task->Run(v, &running))) {
			ran = true;
			if (running)
				running->Release();
			LOG("[DSE-DLL] Elevation task '%ls' launched.\n", taskName);
		} else {
			LOG("[DSE-DLL] Elevation task '%ls' Run() failed (permissions?), falling back.\n", taskName);
		}
	}

done:
	if (bstr)
		SysFreeString(bstr);
	if (exec)
		exec->Release();
	if (action)
		action->Release();
	if (actions)
		actions->Release();
	if (principal)
		principal->Release();
	if (def)
		def->Release();
	if (task)
		task->Release();
	if (folder)
		folder->Release();
	if (svc)
		svc->Release();
	if (uninit)
		CoUninitialize();
	return ran;
}

static void RelaunchElevatedAndExit() {
	WCHAR exePath[MAX_PATH]{};
	GetModuleFileNameW(nullptr, exePath, MAX_PATH);

	if (RunPreRegisteredElevationTask(exePath)) {
		LOG("[DSE-DLL] Elevated via scheduled task, terminating non-admin instance.\n");
		ExitProcess(0);
	}

	LOG("[DSE-DLL] Not admin, no valid task, spawning dse_elevator.exe ...\n");

	WCHAR workDir[MAX_PATH]{};
	lstrcpynW(workDir, exePath, MAX_PATH);
	PathRemoveFileSpecW(workDir);

	WCHAR elevatorPath[MAX_PATH]{};
	GetDseTempPath(L"dse_elevator.exe", elevatorPath);

	if (GetFileAttributesW(elevatorPath) == INVALID_FILE_ATTRIBUTES) {
		HANDLE hFile = CreateFileW(elevatorPath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (hFile != INVALID_HANDLE_VALUE) {
			DWORD written = 0;
			WriteFile(hFile, bin_elevator, bin_elevator_len, &written, nullptr);
			CloseHandle(hFile);
		}
	}

	// wsprintfW stops at 1024 chars, which cut off long game command lines.
	LPCWSTR cmdArgs = PathGetArgsW(GetCommandLineW());
	WCHAR cmdLine[8192]{};
	if (cmdArgs && cmdArgs[0])
		_snwprintf_s(cmdLine, ARRAYSIZE(cmdLine), _TRUNCATE, L"\"%ls\" \"%ls\" \"%ls\"", elevatorPath, exePath, cmdArgs);
	else
		_snwprintf_s(cmdLine, ARRAYSIZE(cmdLine), _TRUNCATE, L"\"%ls\" \"%ls\"", elevatorPath, exePath);

	STARTUPINFOW si = {sizeof(si)};
	PROCESS_INFORMATION pi{};
	if (CreateProcessW(elevatorPath, cmdLine, nullptr, nullptr, FALSE, 0, nullptr, workDir, &si, &pi)) {
		LOG("[DSE-DLL] Elevator launched, waiting for UAC...\n");
		WaitForSingleObject(pi.hProcess, INFINITE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	} else {
		LOG("[DSE-DLL] Failed to launch elevator: %lu\n", GetLastError());
	}

	DeleteFileW(elevatorPath);

	LOG("[DSE-DLL] Terminating non-admin instance.\n");
	ExitProcess(0);
}

pCreateProcessW_t OriginalCreateProcessW = nullptr;
static decltype(&CreateWindowExW) OriginalCreateWindowExW = nullptr;

static void GetLaunchedExePath(LPCWSTR app, LPCWSTR cmdLine, WCHAR (&out)[MAX_PATH]) {
	if (app && app[0]) {
		lstrcpynW(out, app, MAX_PATH);
		return;
	}
	if (!cmdLine || !cmdLine[0])
		return;
	int argc = 0;
	LPWSTR *argv = CommandLineToArgvW(cmdLine, &argc);
	if (!argv)
		return;
	if (argc > 0)
		lstrcpynW(out, argv[0], MAX_PATH);
	LocalFree(argv);
}

static bool ShouldPassThrough(LPCWSTR exePath, LPCWSTR curDir) {
	static WCHAR s_gameDir[MAX_PATH]{};
	if (!s_gameDir[0] && GetModuleFileNameW(nullptr, s_gameDir, MAX_PATH)) {
		PathRemoveFileSpecW(s_gameDir);
		PathAddBackslashW(s_gameDir);
	}

	WCHAR resolved[MAX_PATH]{};
	if (!PathIsRelativeW(exePath)) {
		lstrcpynW(resolved, exePath, MAX_PATH);
	} else {
		WCHAR cwd[MAX_PATH]{};
		LPCWSTR base = (curDir && curDir[0]) ? curDir : (GetCurrentDirectoryW(MAX_PATH, cwd) ? cwd : nullptr);
		if (base)
			PathCombineW(resolved, base, exePath);
	}

	LPCWSTR checkPath = resolved[0] ? resolved : exePath;
	if (s_gameDir[0] && StrStrIW(checkPath, s_gameDir) != checkPath)
		return true;
	return IsPassthroughExe(PathFindFileNameW(exePath));
}

BOOL WINAPI HookedCreateProcessW(
	LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles,
	DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {

	auto passthrough = [&]() {
		return OriginalCreateProcessW(
			lpApplicationName, lpCommandLine, lpProcessAttributes,
			lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
			lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
	};

	WCHAR exePath[MAX_PATH]{};
	GetLaunchedExePath(lpApplicationName, lpCommandLine, exePath);
	if (exePath[0] && ShouldPassThrough(exePath, lpCurrentDirectory))
		return passthrough();

	LOG("[DSE-DLL] CreateProcessW intercepted: %ls\n",
		lpCommandLine ? lpCommandLine : L"(null)");

	if (g_targetExe[0] && (!exePath[0] || !StrStrIW(PathFindFileNameW(exePath), g_targetExe))) {
		LOG("[DSE-DLL] Exe does not match target '%ls', passing through\n", g_targetExe);
		return passthrough();
	}

	if (g_isLauncher) {
		LOG("[DSE-DLL] CreateProcessW > launcher mode (skipping disabling dse)\n");
	} else if (g_config.toggleDse && !g_wasOffFromStart) {
		if (IsDseEnabledNtdll()) {
			LOG("[DSE-DLL] CreateProcessW > disabling DSE\n");
			DisableDse();
		} else {
			LOG("[DSE-DLL] CreateProcessW > DSE already disabled\n");
		}
	}

	BOOL ok = OriginalCreateProcessW(
		lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
		bInheritHandles, dwCreationFlags | CREATE_SUSPENDED, lpEnvironment,
		lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

	if (ok && lpProcessInformation) {
		WCHAR dllPath[MAX_PATH]{};
		GetModuleFileNameW(g_hModule, dllPath, MAX_PATH);
		InjectDll(lpProcessInformation->hProcess, dllPath);
		if (!(dwCreationFlags & CREATE_SUSPENDED))
			ResumeThread(lpProcessInformation->hThread);
	}

	return ok;
}

BOOL WINAPI HookedCreateProcessWithTokenW(
	HANDLE hToken, DWORD dwLogonFlags, LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine, DWORD dwCreationFlags, LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation) {
	(void)hToken;
	(void)dwLogonFlags;

	LOG("[DSE-DLL] CreateProcessWithTokenW -> redirecting to CreateProcessW\n");
	return HookedCreateProcessW(lpApplicationName, lpCommandLine, nullptr,
								nullptr, FALSE, dwCreationFlags, lpEnvironment,
								lpCurrentDirectory, lpStartupInfo,
								lpProcessInformation);
}

HWND WINAPI HookedCreateWindowExW(DWORD dwExStyle, LPCWSTR lpClassName,
								  LPCWSTR lpWindowName, DWORD dwStyle, int X,
								  int Y, int nWidth, int nHeight,
								  HWND hWndParent, HMENU hMenu,
								  HINSTANCE hInstance, LPVOID lpParam) {
	HWND hwnd = OriginalCreateWindowExW(dwExStyle, lpClassName, lpWindowName,
										dwStyle, X, Y, nWidth, nHeight,
										hWndParent, hMenu, hInstance, lpParam);

	static bool s_dseRestored = false;
	if (!s_dseRestored && g_config.toggleDse && !g_wasOffFromStart && !g_isLauncher && hwnd != nullptr) {
		s_dseRestored = true;
		if (g_wasToggled) {
			LOG("[DSE-DLL] Window created > we disabled DSE earlier, restoring now...\n");
			EnableDse();
		} else {
			LOG("[DSE-DLL] Window created > DSE wasn't disabled by us, skipping\n");
		}
	}
	return hwnd;
}

static void InitializeHooks() {
	LOG("[DSE-DLL] Initializing MinHook...\n");
	if (MH_Initialize() != MH_OK) {
		LOG("[DSE-DLL] MinHook init failed!\n");
		return;
	}

	HookApi(L"kernel32.dll", "CreateProcessW",
			(LPVOID)&HookedCreateProcessW, (LPVOID *)&OriginalCreateProcessW);
	HookApi(L"user32.dll", "CreateWindowExW",
			(LPVOID)&HookedCreateWindowExW, (LPVOID *)&OriginalCreateWindowExW);
	HookApi(L"advapi32.dll", "CreateProcessWithTokenW",
			(LPVOID)&HookedCreateProcessWithTokenW, nullptr);

	LOG("[DSE-DLL] Hooks installed\n");
}

static void PrepareDse() {
	WaitForWatchdogToExit();
	if (IsDseEnabledNtdll()) {
		LOG("[DSE-DLL] Running as ADMIN, disabling DSE...\n");
		DisableDse();
		SetDseToggled();
		g_wasToggled = true;
	} else if (CheckAndSetDseToggled()) {
		LOG("[DSE-DLL] DSE off (parent disabled it), proceeding normally\n");
		g_wasToggled = true;
	} else {
		LOG("[DSE-DLL] DSE off from start (testsigning etc.)\n");
		SetDseOffFromStart();
		g_wasOffFromStart = true;
	}
}

static void OnProcessAttach(HMODULE hModule) {
	DisableThreadLibraryCalls(hModule);
	g_hModule = hModule;

	LoadDseConfig(hModule);
	g_loggingEnabled = g_config.logging;

	HideModule();

	if (IsHostPassthrough())
		return;

	SetupLogConsole(g_hModule);

	LOG("[DSE-DLL] Attached to PID %lu\n", GetCurrentProcessId());
	LOG("[DSE-DLL] Config: toggleDse=%d steamHooks=%d logging=%d\n",
		g_config.toggleDse, g_config.steamHooks, g_config.logging);

	if (g_config.toggleDse && !IsRunningAsAdmin())
		RelaunchElevatedAndExit();

	g_isLauncher = DetectLauncherTarget(g_targetExe, ARRAYSIZE(g_targetExe));
	if (g_config.toggleDse) {
		ManageProblematicServices();
		ManageProblematicTasks();
	}

	CheckAndSetAfterburnerEvent();
	if (g_config.toggleDse && IsAfterburnerRunning())
		SetAfterburnerRunningState(true);

	SystemChecks();

	if (g_config.toggleDse)
		PrepareDse();
	else
		LOG("[DSE-DLL] DSE toggling disabled by config\n");

	InitializeHooks();
	if (g_config.steamHooks) {
		InitSteamHooks();
		if (g_config.coldloaderhooks)
			InitSteamColdHooks();
	} else {
		LOG("[DSE-DLL] Steam hooks disabled by config\n");
	}
	if (g_config.steamApiForward)
		InitSteamApiForward();

	if (g_isLauncher)
		LOG("[DSE-DLL] Launcher detected, skipping watchdog\n");
	else if (g_config.toggleDse)
		SpawnWatchdog(g_wasOffFromStart, g_wasToggled);
	else
		LOG("[DSE-DLL] DSE toggling disabled, skipping watchdog\n");
}

static void OnProcessDetach() {
	if (IsHostPassthrough())
		return;

	LOG("[DSE-DLL] Detaching...\n");
	CloseDseEvents();

	bool otherGameRunning = IsOtherGameRunning();

	if (g_config.toggleDse && !g_wasOffFromStart) {
		if (IsDseEnabledNtdll())
			LOG("[DSE-DLL] Detaching > DSE already enabled, skipping\n");
		else if (otherGameRunning)
			LOG("[DSE-DLL] Detaching > another game is running, skipping restore\n");
		else {
			LOG("[DSE-DLL] Detaching... restoring DSE...\n");
			EnableDse();
		}
	}

	if (g_config.toggleDse && !otherGameRunning)
		RestoreProblematicServices();

	FreeDseConfig();

	LOG("[DSE-DLL] Uninitializing MinHook...\n");
	MH_Uninitialize();
	LOG("[DSE-DLL] Deleting patcher...\n");
	DeletePatcherFile();
	LOG("[DSE-DLL] Detached!\n");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call,
					  LPVOID lpReserved) {
	(void)lpReserved;

	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
		OnProcessAttach(hModule);
	else if (ul_reason_for_call == DLL_PROCESS_DETACH)
		OnProcessDetach();

	return TRUE;
}
