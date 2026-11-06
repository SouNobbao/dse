#pragma once

#include <windows.h>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ConfigManager {
    std::wstring GetDriversIniPath();
    std::wstring GetDriverPath();
    bool UpdateDriversIni(uint64_t seCiCallbacks, uint64_t safeFunction);
    bool SaveOffsetsToRegistry(uint64_t seCiCallbacks, uint64_t safeFunction, const std::wstring& buildInfo);
    bool SaveOriginalCallbackToRegistry(uint64_t callback);
    std::optional<uint64_t> LoadOriginalCallbackFromRegistry();
    bool ClearPatchStateFromRegistry();
    bool IsPatchedFromRegistry();
    bool SaveOriginalCiOptionsToRegistry(uint32_t value);
    std::optional<uint32_t> LoadOriginalCiOptionsFromRegistry();
    std::wstring GetWindowsBuildNumber();
}
