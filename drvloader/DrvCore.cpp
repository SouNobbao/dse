#include "DrvCore.h"
#include "ConfigManager.h"
#include "ResourceInstaller.h"
#include "drvlog.h"
#include <vector>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "version.lib")

bool DrvLoader::Initialize() {
    originalCallback = ConfigManager::LoadOriginalCallbackFromRegistry();

    if (originalCallback) {
        DRVLOG(L"Found previous patch state in registry\n");
    } else {
        DRVLOG(L"No previous patch state found\n");
    }

    if (!symbolDownloader.Initialize()) {
        DRVLOG(L"Failed to initialize symbol downloader\n");
        return false;
    }

    return true;
}

void DrvLoader::Cleanup() {
    if (hDriver != INVALID_HANDLE_VALUE) {
        CloseHandle(hDriver);
        hDriver = INVALID_HANDLE_VALUE;
    }
}

bool DrvLoader::WriteMemory32(uint64_t address, uint32_t value) {
    if (hDriver == INVALID_HANDLE_VALUE) return false;

    RTC_MEMORY_WRITE writePacket{};
    writePacket.Address = address;
    writePacket.Size = sizeof(uint32_t);
    writePacket.Value = value;

    DWORD bytesReturned = 0;
    return DeviceIoControl(hDriver, RTC_IOCTL_MEMORY_WRITE, &writePacket, sizeof(writePacket),
                          &writePacket, sizeof(writePacket), &bytesReturned, nullptr);
}

bool DrvLoader::WriteMemory64(uint64_t address, uint64_t value) {
    return WriteMemory32(address, static_cast<uint32_t>(value & 0xFFFFFFFF)) &&
           WriteMemory32(address + 4, static_cast<uint32_t>((value >> 32) & 0xFFFFFFFF));
}

std::optional<uint32_t> DrvLoader::ReadMemory32(uint64_t address) {
    if (hDriver == INVALID_HANDLE_VALUE) return std::nullopt;

    RTC_MEMORY_READ readPacket{};
    readPacket.Address = address;
    readPacket.Size = sizeof(uint32_t);

    DWORD bytesReturned = 0;
    if (!DeviceIoControl(hDriver, RTC_IOCTL_MEMORY_READ, &readPacket, sizeof(readPacket),
                        &readPacket, sizeof(readPacket), &bytesReturned, nullptr))
        return std::nullopt;

    return readPacket.Value;
}

std::optional<uint64_t> DrvLoader::ReadMemory64(uint64_t address) {
    auto low = ReadMemory32(address);
    auto high = ReadMemory32(address + 4);
    if (!low || !high) return std::nullopt;

    return (static_cast<uint64_t>(*high) << 32) | *low;
}

std::optional<uint64_t> DrvLoader::GetNtoskrnlBase() {
    std::vector<LPVOID> drivers(1024);
    DWORD needed = 0;

    if (!EnumDeviceDrivers(drivers.data(), static_cast<DWORD>(drivers.size() * sizeof(LPVOID)), &needed))
        return std::nullopt;

    drivers.resize(needed / sizeof(LPVOID));

    for (const auto& driver : drivers) {
        WCHAR driverName[MAX_PATH];
        if (GetDeviceDriverBaseNameW(driver, driverName, MAX_PATH) && wcscmp(driverName, L"ntoskrnl.exe") == 0) {
            return reinterpret_cast<uint64_t>(driver);
        }
    }

    return std::nullopt;
}

std::optional<std::pair<uint64_t, uint64_t>> DrvLoader::GetTextSectionBounds(const std::wstring& ntoskrnlPath) {
    HANDLE hFile = CreateFileW(ntoskrnlPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return std::nullopt;

    HANDLE hMapping = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMapping) {
        CloseHandle(hFile);
        return std::nullopt;
    }

    LPVOID pBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pBase) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return std::nullopt;
    }

    std::optional<std::pair<uint64_t, uint64_t>> result;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    if (pDos->e_magic == IMAGE_DOS_SIGNATURE) {
        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDos->e_lfanew);
        if (pNt->Signature == IMAGE_NT_SIGNATURE) {
            PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

            for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
                char sectionName[9] = {0};
                memcpy(sectionName, pSection[i].Name, 8);

                if (strcmp(sectionName, ".text") == 0) {
                    uint64_t textStart = pSection[i].VirtualAddress;
                    uint64_t textEnd = textStart + pSection[i].Misc.VirtualSize;
                    result = {textStart, textEnd};
                    break;
                }
            }
        }
    }

    UnmapViewOfFile(pBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    return result;
}

bool DrvLoader::ValidateKernelAddresses(uint64_t ntBase, uint64_t seCiRva, uint64_t zwRva) {
    WCHAR systemRoot[MAX_PATH];
    GetSystemDirectoryW(systemRoot, MAX_PATH);
    std::wstring ntoskrnlPath = std::wstring(systemRoot) + L"\\ntoskrnl.exe";

    auto textBounds = GetTextSectionBounds(ntoskrnlPath);
    if (!textBounds) {
        DRVLOG(L"Failed to read .text section from ntoskrnl.exe\n");
        return false;
    }

    auto [textStart, textEnd] = *textBounds;

    if (zwRva < textStart || zwRva >= textEnd) {
        DRVLOG(L"ZwFlushInstructionCache offset 0x%llX is outside .text section\n", zwRva);
        return false;
    }

    DRVLOG(L"ZwFlushInstructionCache validated in .text section\n");

    uint64_t seCiCallbacks = ntBase + seCiRva;
    uint64_t callbackAddress = seCiCallbacks + 0x20;

    auto testRead = ReadMemory64(callbackAddress);
    if (!testRead) {
        DRVLOG(L"Cannot read SeCiCallbacks+0x20 at 0x%llX\n", callbackAddress);
        return false;
    }

    DRVLOG(L"SeCiCallbacks address validated (readable)\n");
    return true;
}

std::optional<std::pair<uint64_t, uint64_t>> DrvLoader::ResolveKernelOffsetsStrict() {
    WCHAR systemRoot[MAX_PATH];
    GetSystemDirectoryW(systemRoot, MAX_PATH);
    std::wstring ntoskrnlPath = std::wstring(systemRoot) + L"\\ntoskrnl.exe";

    DRVLOG(L"Strict offset resolution from PDB...\n");

    auto [pdbName, pdbGuid] = symbolDownloader.GetPdbInfoFromPe(ntoskrnlPath);
    if (pdbGuid.empty()) {
        DRVLOG(L"Failed to extract PDB GUID from ntoskrnl.exe\n");
        return std::nullopt;
    }

    DRVLOG(L"Current kernel PDB GUID: %ls\n", pdbGuid.c_str());

    if (!symbolDownloader.DownloadSymbolsForModule(ntoskrnlPath)) {
        DRVLOG(L"Failed to obtain PDB symbols\n");
        return std::nullopt;
    }

    auto seCiOpt = symbolDownloader.GetSymbolOffset(ntoskrnlPath, L"SeCiCallbacks");
    auto zwOpt = symbolDownloader.GetSymbolOffset(ntoskrnlPath, L"ZwFlushInstructionCache");

    if (!seCiOpt || !zwOpt) {
        DRVLOG(L"Failed to resolve required symbols from PDB\n");
        return std::nullopt;
    }

    DRVLOG(L"Resolved offsets: SeCiCallbacks=0x%llX ZwFlushInstructionCache=0x%llX\n",
           *seCiOpt, *zwOpt);

    return std::make_pair(*seCiOpt, *zwOpt);
}

bool DrvLoader::GetSymbolOffsets(uint64_t* seCiCallbacks, uint64_t* safeFunction) {
    auto offsets = ResolveKernelOffsetsStrict();
    if (!offsets) return false;

    *seCiCallbacks = offsets->first;
    *safeFunction = offsets->second;
    return true;
}

std::optional<uint64_t> DrvLoader::GetKernelSymbolOffset(const std::wstring& symbolName) {
    WCHAR systemRoot[MAX_PATH];
    GetSystemDirectoryW(systemRoot, MAX_PATH);
    std::wstring ntoskrnlPath = std::wstring(systemRoot) + L"\\ntoskrnl.exe";

    if (!symbolDownloader.DownloadSymbolsForModule(ntoskrnlPath)) return std::nullopt;
    return symbolDownloader.GetSymbolOffset(ntoskrnlPath, symbolName);
}

bool DrvLoader::CheckDriverFileExists() {
    std::wstring driverPath = ConfigManager::GetDriverPath();
    if (GetFileAttributesW(driverPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        DRVLOG(L"Installing driver from embedded resource...\n");
        if (!embeddedResourceData || embeddedResourceSize == 0) {
            DRVLOG(L"No embedded resource data set!\n");
            return false;
        }
        if (!ResourceInstaller::InstallDriverFromEmbeddedData(embeddedResourceData, embeddedResourceSize))
            return false;

        if (GetFileAttributesW(driverPath.c_str()) == INVALID_FILE_ATTRIBUTES) return false;
    }
    return true;
}

bool DrvLoader::StopAndRemoveDriver() {
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) return false;

    SC_HANDLE hService = OpenServiceW(hSCM, L"RTCore64", SERVICE_ALL_ACCESS);
    if (hService) {
        SERVICE_STATUS serviceStatus;
        ControlService(hService, SERVICE_CONTROL_STOP, &serviceStatus);
        DeleteService(hService);
        CloseServiceHandle(hService);
    }

    CloseServiceHandle(hSCM);
    return true;
}

void DrvLoader::DeleteDriverFile() {
    std::wstring sysPath = ConfigManager::GetDriverPath();
    DeleteFileW(sysPath.c_str());
}

bool DrvLoader::InstallAndStartDriver() {
    if (!CheckDriverFileExists()) return false;
    StopAndRemoveDriver();

    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) return false;

    std::wstring driverPath = L"\\??\\" + ConfigManager::GetDriverPath();

    SC_HANDLE hService = CreateServiceW(hSCM, L"RTCore64", L"RTCore64", SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        driverPath.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);

    if (!hService) {
        CloseServiceHandle(hSCM);
        return false;
    }

    StartServiceW(hService, 0, nullptr);
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return true;
}

bool DrvLoader::CheckDSEStatus(bool& isPatched) {
    DRVLOG(L"Checking DSE Status...\n");

    auto offsets = ResolveKernelOffsetsStrict();
    if (!offsets) {
        DRVLOG(L"Failed to resolve kernel offsets\n");
        return false;
    }

    auto [seCiCallbacksOffset, zwFlushOffset] = *offsets;

    if (!InstallAndStartDriver()) return false;

    hDriver = CreateFileW(L"\\\\.\\RTCore64", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDriver == INVALID_HANDLE_VALUE) {
        StopAndRemoveDriver();
        DeleteDriverFile();
        return false;
    }

    auto ntBase = GetNtoskrnlBase();
    if (!ntBase) {
        Cleanup();
        StopAndRemoveDriver();
        DeleteDriverFile();
        return false;
    }

    DRVLOG(L"ntoskrnl.exe base: 0x%llX\n", *ntBase);

    if (!ValidateKernelAddresses(*ntBase, seCiCallbacksOffset, zwFlushOffset)) {
        DRVLOG(L"Address validation failed\n");
        Cleanup();
        StopAndRemoveDriver();
        DeleteDriverFile();
        return false;
    }

    uint64_t seCiCallbacks = *ntBase + seCiCallbacksOffset;
    uint64_t safeFunction = *ntBase + zwFlushOffset;
    uint64_t callbackAddress = seCiCallbacks + 0x20;

    auto currentCallback = ReadMemory64(callbackAddress);
    if (!currentCallback) {
        Cleanup();
        StopAndRemoveDriver();
        DeleteDriverFile();
        return false;
    }

    isPatched = (*currentCallback == safeFunction);

    DRVLOG(L"DSE Status: %ls\n", isPatched ? L"PATCHED" : L"ACTIVE");

    ConfigManager::UpdateDriversIni(seCiCallbacksOffset, zwFlushOffset);
    std::wstring buildInfo = ConfigManager::GetWindowsBuildNumber();
    ConfigManager::SaveOffsetsToRegistry(seCiCallbacksOffset, zwFlushOffset, buildInfo);

    Cleanup();
    StopAndRemoveDriver();
    DeleteDriverFile();
    return true;
}

bool DrvLoader::BypassDSEInternal() {
    auto offsets = ResolveKernelOffsetsStrict();
    if (!offsets) {
        DRVLOG(L"Failed to resolve kernel offsets\n");
        return false;
    }

    auto [seCiOffset, zwFlushOffset] = *offsets;

    auto ntBase = GetNtoskrnlBase();
    if (!ntBase) {
        DRVLOG(L"Failed to get ntoskrnl.exe base address\n");
        return false;
    }

    DRVLOG(L"ntoskrnl.exe base: 0x%llX\n", *ntBase);

    if (!ValidateKernelAddresses(*ntBase, seCiOffset, zwFlushOffset)) {
        DRVLOG(L"Address validation failed - aborting patch\n");
        return false;
    }

    uint64_t seCiCallbacks = *ntBase + seCiOffset;
    uint64_t safeFunction = *ntBase + zwFlushOffset;
    uint64_t callbackToPatch = seCiCallbacks + 0x20;

    auto currentCallback = ReadMemory64(callbackToPatch);
    if (!currentCallback) {
        DRVLOG(L"Failed to read current callback\n");
        return false;
    }

    if (*currentCallback == safeFunction) {
        DRVLOG(L"DSE already bypassed\n");
        return true;
    }

    DRVLOG(L"Patching callback: 0x%llX -> 0x%llX\n", *currentCallback, safeFunction);

    originalCallback = *currentCallback;
    if (!ConfigManager::SaveOriginalCallbackToRegistry(*originalCallback)) {
        DRVLOG(L"Failed to save original callback to registry\n");
        return false;
    }

    if (!WriteMemory64(callbackToPatch, safeFunction)) {
        DRVLOG(L"Failed to write patched callback\n");
        return false;
    }

    auto verifyCallback = ReadMemory64(callbackToPatch);
    if (!verifyCallback || *verifyCallback != safeFunction) {
        DRVLOG(L"Patch verification failed\n");
        return false;
    }

    DRVLOG(L"DSE bypass successful\n");
    return true;
}

bool DrvLoader::BypassDSE() {
    DRVLOG(L"DSE Bypass...\n");

    if (!InstallAndStartDriver()) return false;

    hDriver = CreateFileW(L"\\\\.\\RTCore64", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDriver == INVALID_HANDLE_VALUE) {
        StopAndRemoveDriver();
        DeleteDriverFile();
        return false;
    }

    bool result = BypassDSEInternal();

    Cleanup();
    StopAndRemoveDriver();
    DeleteDriverFile();
    return result;
}

bool DrvLoader::RestoreDSEInternal() {
    if (!originalCallback) {
        DRVLOG(L"No original callback value available\n");
        return false;
    }

    auto offsets = ResolveKernelOffsetsStrict();
    if (!offsets) {
        DRVLOG(L"Failed to resolve kernel offsets\n");
        return false;
    }

    auto [seCiOffset, zwFlushOffset] = *offsets;

    auto ntBase = GetNtoskrnlBase();
    if (!ntBase) {
        DRVLOG(L"Failed to get ntoskrnl.exe base address\n");
        return false;
    }

    if (!ValidateKernelAddresses(*ntBase, seCiOffset, zwFlushOffset)) {
        DRVLOG(L"Address validation failed\n");
        return false;
    }

    uint64_t callbackAddress = *ntBase + seCiOffset + 0x20;

    auto currentCallback = ReadMemory64(callbackAddress);
    if (!currentCallback) {
        DRVLOG(L"Failed to read current callback\n");
        return false;
    }

    if (*currentCallback == *originalCallback) {
        DRVLOG(L"DSE already restored\n");
        ConfigManager::ClearPatchStateFromRegistry();
        return true;
    }

    DRVLOG(L"Restoring callback: 0x%llX -> 0x%llX\n", *currentCallback, *originalCallback);

    if (WriteMemory64(callbackAddress, *originalCallback)) {
        auto verifyCallback = ReadMemory64(callbackAddress);
        if (!verifyCallback || *verifyCallback != *originalCallback) {
            DRVLOG(L"Restoration verification failed\n");
            return false;
        }

        DRVLOG(L"DSE restored successfully\n");
        ConfigManager::ClearPatchStateFromRegistry();
        return true;
    }

    DRVLOG(L"Failed to restore callback\n");
    return false;
}

bool DrvLoader::RestoreDSE() {
    DRVLOG(L"Restore DSE...\n");
    if (!originalCallback) {
        DRVLOG(L"No original callback state known\n");
        return false;
    }

    if (!InstallAndStartDriver()) return false;

    hDriver = CreateFileW(L"\\\\.\\RTCore64", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDriver == INVALID_HANDLE_VALUE) {
        StopAndRemoveDriver();
        DeleteDriverFile();
        return false;
    }

    bool result = RestoreDSEInternal();

    Cleanup();
    StopAndRemoveDriver();
    DeleteDriverFile();
    return result;
}
