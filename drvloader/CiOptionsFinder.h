#pragma once

#include <Windows.h>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>

class DrvLoader;

class CiOptionsFinder {
public:
    explicit CiOptionsFinder(DrvLoader* loader) noexcept;
    uint64_t FindCiOptions(uint64_t ciBase) noexcept;

private:
    DrvLoader* m_loader;

    std::optional<std::pair<uint64_t, size_t>> GetCiPolicySectionFromDisk(
        const std::wstring& ciPath, uint64_t ciBase) noexcept;

    std::optional<DWORD> FindCiOptionsOffsetFromCiPolicy(
        const std::wstring& ciPath, uint64_t ciPolicyStart, size_t ciPolicySize) noexcept;

    std::optional<DWORD> GetCiOptionsBuildFallbackOffset() noexcept;

    std::optional<uint64_t> FindCiOptionsInDataSection(
        const std::wstring& ciPath, uint64_t ciBase) noexcept;

    std::optional<std::wstring> GetCiDllPath() noexcept;
};
