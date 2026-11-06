#pragma once

#include <windows.h>
#include <vector>
#include <cstdint>

namespace ResourceInstaller {
    constexpr BYTE XOR_KEY[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };
    constexpr size_t XOR_KEY_LEN = sizeof(XOR_KEY);

    std::vector<BYTE> ExtractAndDecryptDriverFromMemory(const BYTE* resData, size_t resSize);

    bool InstallDriverFromEmbeddedData(const BYTE* resData, size_t resSize);

    bool IsDriverInstalled();
}
