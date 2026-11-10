#define WIN32_LEAN_AND_MEAN

#include "elevation.h"

#include "common.h"
#include "log.h"

#include <filesystem>
#include <shlwapi.h>
#include <taskschd.h>
#include <windows.h>

#pragma comment(lib, "shlwapi.lib")

#include "elevator_bin.cpp"

static bool StartScheduledProcess(LPCWSTR selfExePath) {
	std::wstring taskName = L"dse_" + std::filesystem::path(selfExePath).stem().native();

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

	bstr = SysAllocString(taskName.c_str());
	if (FAILED(folder->GetTask(bstr, &task)) || !task) {
		LOG("Elevation task '%ls' not registered.\n", taskName.c_str());
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
			LOG("Elevation task '%ls' is not highest run level, ignoring.\n",
				taskName.c_str());
			goto done;
		}
	}

	// exactly one exec action, whose path is this exact exe.
	if (FAILED(def->get_Actions(&actions)))
		goto done;
	{
		LONG count = 0;
		if (FAILED(actions->get_Count(&count)) || count != 1) {
			LOG("Elevation task '%ls' has %ld actions (want 1), ignoring.\n",
				taskName.c_str(), count);
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
		LOG("Elevation task path mismatch ('%ls' != '%ls'), ignoring.\n",
			bstr, selfExePath);
		goto done;
	}
	SysFreeString(bstr);
	bstr = nullptr;

	{
		const std::filesystem::path exeDir = std::filesystem::path(selfExePath).parent_path();
		if (FAILED(exec->get_WorkingDirectory(&bstr)) || !bstr)
			goto done;
		const std::filesystem::path taskDir(bstr);
		if (_wcsicmp(exeDir.c_str(), taskDir.c_str()) != 0) {
			LOG("Elevation task working dir mismatch ('%ls' != '%ls'), ignoring.\n",
				taskDir.c_str(), exeDir.c_str());
			goto done;
		}
	}
	SysFreeString(bstr);
	bstr = nullptr;

	{
		IRunningTask *running = nullptr;
		if (SUCCEEDED(task->Run(v, &running))) {
			ran = true;
			if (running)
				running->Release();
			LOG("Elevation task '%ls' launched.\n", taskName.c_str());
		} else {
			LOG("Elevation task '%ls' Run() failed (permissions?), falling back.\n",
				taskName.c_str());
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

void RelaunchElevatedAndExit() {
	WCHAR selfExePath[MAX_PATH]{};
	GetModuleFileNameW(nullptr, selfExePath, MAX_PATH);

	if (StartScheduledProcess(selfExePath)) {
		LOG("Elevated via scheduled task, terminating non-admin instance.\n");
		ExitProcess(0);
	}

	LOG("Not admin, no valid task, spawning dse_elevator.exe ...\n");

	const std::filesystem::path tempDir = GetDseTempDir();
	if (tempDir.empty()) {
		LOG("Temp dir unavailable, cannot spawn elevator\n");
		ExitProcess(0);
	}
	const std::filesystem::path elevatorPath = tempDir / L"dse_elevator.exe";

	std::error_code ec;
	if (!std::filesystem::exists(elevatorPath, ec)) {
		HANDLE hFile = CreateFileW(elevatorPath.c_str(), GENERIC_WRITE, 0, nullptr,
								   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (hFile != INVALID_HANDLE_VALUE) {
			DWORD written = 0;
			WriteFile(hFile, bin_elevator, bin_elevator_len, &written, nullptr);
			CloseHandle(hFile);
		}
	}

	std::wstring cmdLine =
		L"\"" + elevatorPath.wstring() + L"\" \"" + std::wstring(selfExePath) + L"\"";
	LPCWSTR cmdArgs = PathGetArgsW(GetCommandLineW());
	if (cmdArgs && cmdArgs[0])
		cmdLine += std::wstring(L" \"") + cmdArgs + L"\"";

	STARTUPINFOW si = {sizeof(si)};
	PROCESS_INFORMATION pi{};
	if (CreateProcessW(elevatorPath.c_str(), cmdLine.data(), nullptr, nullptr, FALSE,
					   0, nullptr, std::filesystem::path(selfExePath).parent_path().c_str(), &si, &pi)) {
		LOG("Elevator launched, waiting for UAC...\n");
		WaitForSingleObject(pi.hProcess, INFINITE);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	} else {
		LOG("Failed to launch elevator: %lu\n", GetLastError());
	}

	std::filesystem::remove(elevatorPath, ec);

	LOG("Terminating non-admin instance.\n");
	ExitProcess(0);
}
