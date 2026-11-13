#pragma once

#include <windows.h>
#include <dbghelp.h>
#include <winhttp.h>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include <utility>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "winhttp.lib")

class SymbolDownloader {
private:
    std::wstring symbolCachePath;
    std::wstring symbolServer;
    bool useProgramDataStore;
    bool EnsureSymbolCache();
    bool DownloadPdb(const std::wstring& modulePath);
    bool DownloadFile(const std::wstring& url, const std::wstring& outputPath);
    std::wstring GetProgramDataSymbolPath();

public:
    SymbolDownloader(const std::wstring& cachePath = L"", bool useProgramData = true);

    bool Initialize();
    std::optional<uint64_t> GetSymbolOffset(const std::wstring& moduleName, const std::wstring& symbolName);
    bool DownloadSymbolsForModule(const std::wstring& modulePath);
    std::pair<std::wstring, std::wstring> GetPdbInfoFromPe(const std::wstring& pePath);
    std::wstring GetSymbolCachePath() const { return symbolCachePath; }

};
