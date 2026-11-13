#include "SymbolDownloader.h"
#include "drvlog.h"
#include <shlobj.h>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")

SymbolDownloader::SymbolDownloader(const std::wstring &cachePath,
                                   bool useProgramData)
    : symbolServer(L"https://msdl.microsoft.com/download/symbols"),
      useProgramDataStore(useProgramData) {

  if (!cachePath.empty()) {
    symbolCachePath = cachePath;
    useProgramDataStore = false;
  } else if (useProgramDataStore) {
    symbolCachePath = GetProgramDataSymbolPath();
  } else {
    WCHAR exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    PathRemoveFileSpecW(exePath);
    symbolCachePath = std::wstring(exePath) + L"\\symbols";
  }
}

std::wstring SymbolDownloader::GetProgramDataSymbolPath() {
  WCHAR progData[MAX_PATH];
  if (SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, progData) ==
      S_OK) {
    return std::wstring(progData) + L"\\dbg\\sym";
  }
  return L"C:\\ProgramData\\dbg\\sym";
}

bool SymbolDownloader::Initialize() {
  if (!EnsureSymbolCache()) {
    return false;
  }

  SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_DEBUG);

  if (!SymInitializeW(GetCurrentProcess(), symbolCachePath.c_str(), FALSE)) {
    DRVLOG(L"Failed to initialize symbol handler (error: %lu)\n", GetLastError());
    return false;
  }

  DRVLOG(L"Symbol handler initialized, cache: %ls\n", symbolCachePath.c_str());
  return true;
}

bool SymbolDownloader::EnsureSymbolCache() {
  DWORD attrib = GetFileAttributesW(symbolCachePath.c_str());

  if (attrib == INVALID_FILE_ATTRIBUTES) {
    if (SHCreateDirectoryExW(nullptr, symbolCachePath.c_str(), nullptr) !=
        ERROR_SUCCESS) {
      DRVLOG(L"Failed to create symbol cache directory: %ls\n", symbolCachePath.c_str());
      return false;
    }
    DRVLOG(L"Created symbol cache directory: %ls\n", symbolCachePath.c_str());
  }

  return true;
}

std::pair<std::wstring, std::wstring>
SymbolDownloader::GetPdbInfoFromPe(const std::wstring &pePath) {
  HANDLE hFile = CreateFileW(pePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                             nullptr, OPEN_EXISTING, 0, nullptr);
  if (hFile == INVALID_HANDLE_VALUE)
    return {L"", L""};

  HANDLE hMapping =
      CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
  if (!hMapping) {
    CloseHandle(hFile);
    return {L"", L""};
  }

  LPVOID pBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
  if (!pBase) {
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return {L"", L""};
  }

  std::wstring guidStr, pdbName;

  auto RvaToOffset = [](PIMAGE_SECTION_HEADER secs, WORD n,
                        DWORD rva) -> DWORD {
    for (WORD i = 0; i < n; i++) {
      DWORD va = secs[i].VirtualAddress;
      DWORD raw = secs[i].SizeOfRawData;
      if (rva >= va && rva < va + raw)
        return (rva - va) + secs[i].PointerToRawData;
    }
    return 0;
  };

  struct CV_INFO_PDB70 {
    DWORD CvSignature;
    GUID Signature;
    DWORD Age;
    char PdbFileName[1];
  };

  PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
  if (pDos->e_magic == IMAGE_DOS_SIGNATURE) {
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE *)pBase + pDos->e_lfanew);
    if (pNt->Signature == IMAGE_NT_SIGNATURE) {

      PIMAGE_SECTION_HEADER secs = IMAGE_FIRST_SECTION(pNt);
      WORD numSecs = pNt->FileHeader.NumberOfSections;

      DWORD debugRva =
          pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG]
              .VirtualAddress;
      DWORD debugSize =
          pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;

      if (debugRva && debugSize) {
        DWORD debugOffset = RvaToOffset(secs, numSecs, debugRva);
        if (!debugOffset)
          goto cleanup;

        PIMAGE_DEBUG_DIRECTORY pDbgDir =
            (PIMAGE_DEBUG_DIRECTORY)((BYTE *)pBase + debugOffset);

        DWORD count = debugSize / sizeof(IMAGE_DEBUG_DIRECTORY);
        for (DWORD i = 0; i < count; i++) {
          if (pDbgDir[i].Type != IMAGE_DEBUG_TYPE_CODEVIEW)
            continue;

          DWORD cvOffset = pDbgDir[i].PointerToRawData;
          if (!cvOffset)
            continue;

          CV_INFO_PDB70 *pCv = (CV_INFO_PDB70 *)((BYTE *)pBase + cvOffset);
          if (pCv->CvSignature != 0x53445352)
            continue; // 'RSDS'

          wchar_t guidBuf[64];
          swprintf_s(guidBuf, L"%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%X",
                     pCv->Signature.Data1, pCv->Signature.Data2,
                     pCv->Signature.Data3, pCv->Signature.Data4[0],
                     pCv->Signature.Data4[1], pCv->Signature.Data4[2],
                     pCv->Signature.Data4[3], pCv->Signature.Data4[4],
                     pCv->Signature.Data4[5], pCv->Signature.Data4[6],
                     pCv->Signature.Data4[7], pCv->Age);
          guidStr = guidBuf;

          int len =
              MultiByteToWideChar(CP_UTF8, 0, pCv->PdbFileName, -1, nullptr, 0);
          if (len > 0) {
            std::vector<wchar_t> wide(len);
            MultiByteToWideChar(CP_UTF8, 0, pCv->PdbFileName, -1, wide.data(),
                                len);
            std::wstring fullPath = wide.data();
            size_t pos = fullPath.find_last_of(L"\\/");
            pdbName = (pos != std::wstring::npos) ? fullPath.substr(pos + 1)
                                                  : fullPath;
          }
          break;
        }
      }
    }
  }

cleanup:
  UnmapViewOfFile(pBase);
  CloseHandle(hMapping);
  CloseHandle(hFile);
  return {pdbName, guidStr};
}

bool SymbolDownloader::DownloadFile(const std::wstring &url,
                                    const std::wstring &outputPath) {
  DRVLOG(L"Downloading from: %ls\n", url.c_str());

  URL_COMPONENTSW urlParts = {sizeof(urlParts)};
  wchar_t host[256], path[1024];
  urlParts.lpszHostName = host;
  urlParts.dwHostNameLength = _countof(host);
  urlParts.lpszUrlPath = path;
  urlParts.dwUrlPathLength = _countof(path);

  if (!WinHttpCrackUrl(url.c_str(), 0, 0, &urlParts)) {
    DRVLOG(L"Failed to parse URL\n");
    return false;
  }

  HINTERNET hSession =
      WinHttpOpen(L"SymbolDownloader/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                  WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (!hSession) {
    DRVLOG(L"Failed to open HTTP session\n");
    return false;
  }

  HINTERNET hConnect = WinHttpConnect(hSession, host, urlParts.nPort, 0);
  if (!hConnect) {
    DRVLOG(L"Failed to connect to server\n");
    WinHttpCloseHandle(hSession);
    return false;
  }

  HINTERNET hRequest = WinHttpOpenRequest(
      hConnect, L"GET", path, nullptr, WINHTTP_NO_REFERER,
      WINHTTP_DEFAULT_ACCEPT_TYPES,
      urlParts.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0);
  if (!hRequest) {
    DRVLOG(L"Failed to open HTTP request\n");
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return false;
  }

  if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                          WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
    DRVLOG(L"Failed to send HTTP request\n");
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return false;
  }

  if (!WinHttpReceiveResponse(hRequest, nullptr)) {
    DRVLOG(L"Failed to receive HTTP response\n");
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return false;
  }

  DWORD statusCode = 0;
  DWORD statusCodeSize = sizeof(statusCode);
  WinHttpQueryHeaders(hRequest,
                      WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                      WINHTTP_HEADER_NAME_BY_INDEX, &statusCode,
                      &statusCodeSize, WINHTTP_NO_HEADER_INDEX);

  if (statusCode != 200) {
    DRVLOG(L"HTTP error: %lu\n", statusCode);
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return false;
  }

  HANDLE hFile = CreateFileW(outputPath.c_str(), GENERIC_WRITE, 0, nullptr,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (hFile == INVALID_HANDLE_VALUE) {
    DRVLOG(L"Failed to create output file\n");
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return false;
  }

  BYTE buffer[8192];
  DWORD bytesRead = 0, bytesWritten = 0;
  DWORD totalBytes = 0;

  while (WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead) &&
         bytesRead > 0) {
    if (!WriteFile(hFile, buffer, bytesRead, &bytesWritten, nullptr)) {
      DRVLOG(L"Failed to write to file\n");
      CloseHandle(hFile);
      WinHttpCloseHandle(hRequest);
      WinHttpCloseHandle(hConnect);
      WinHttpCloseHandle(hSession);
      return false;
    }
    totalBytes += bytesWritten;
  }

  DRVLOG(L"Downloaded %lu bytes\n", totalBytes);

  CloseHandle(hFile);
  WinHttpCloseHandle(hRequest);
  WinHttpCloseHandle(hConnect);
  WinHttpCloseHandle(hSession);

  return true;
}

bool SymbolDownloader::DownloadPdb(const std::wstring &modulePath) {
  DRVLOG(L"Extracting PDB information from: %ls\n", modulePath.c_str());

  auto [pdbName, guid] = GetPdbInfoFromPe(modulePath);

  if (guid.empty() || pdbName.empty()) {
    DRVLOG(L"Failed to extract PDB info from PE file\n");
    return false;
  }

  DRVLOG(L"PDB Name: %ls, GUID: %ls\n", pdbName.c_str(), guid.c_str());

  std::wstring url =
      symbolServer + L"/" + pdbName + L"/" + guid + L"/" + pdbName;

  std::wstring localDir = symbolCachePath + L"\\" + pdbName + L"\\" + guid;
  std::wstring localPath = localDir + L"\\" + pdbName;

  if (GetFileAttributesW(localPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
    DRVLOG(L"PDB already exists in cache: %ls\n", localPath.c_str());
    return true;
  }

  SHCreateDirectoryExW(nullptr, localDir.c_str(), nullptr);

  if (!DownloadFile(url, localPath)) {
    DRVLOG(L"Failed to download PDB file\n");
    return false;
  }

  DRVLOG(L"PDB downloaded successfully: %ls\n", localPath.c_str());
  return true;
}

bool SymbolDownloader::DownloadSymbolsForModule(
    const std::wstring &modulePath) {
  DRVLOG(L"Resolving symbols for: %ls\n", modulePath.c_str());

  auto [pdbName, guid] = GetPdbInfoFromPe(modulePath);

  if (guid.empty() || pdbName.empty()) {
    DRVLOG(L"Failed to read PE debug info\n");
    return false;
  }

  std::wstring localPath =
      symbolCachePath + L"\\" + pdbName + L"\\" + guid + L"\\" + pdbName;

  if (GetFileAttributesW(localPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
    DRVLOG(L"PDB not in cache, downloading from Microsoft...\n");
    if (!DownloadPdb(modulePath)) {
      DRVLOG(L"Failed to download PDB\n");
      return false;
    }
  } else {
    DRVLOG(L"Using PDB from cache: %ls\n", localPath.c_str());
  }

  if (GetFileAttributesW(localPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
    DRVLOG(L"PDB file does not exist after download attempt\n");
    return false;
  }

  return true;
}

namespace {
  struct ScopedSymbolResult {
    const wchar_t *name;
    DWORD64 address;
    DWORD64 modBase;
    bool found;
  };

  BOOL CALLBACK ScopedSymbolEnum(PSYMBOL_INFOW symbolInfo, ULONG, PVOID context) {
    ScopedSymbolResult *result = (ScopedSymbolResult *)context;
    if (result->found)
      return TRUE;
    if (_wcsicmp(symbolInfo->Name, result->name) == 0) {
      result->address = symbolInfo->Address;
      result->modBase = symbolInfo->ModBase;
      result->found = true;
    }
    return TRUE;
  }

  class ModuleGuard {
    public:
      ModuleGuard(HANDLE process, DWORD64 base) : m_process(process), m_base(base) {}
      ~ModuleGuard() {
        if (m_base)
          SymUnloadModule64(m_process, m_base);
      }
      ModuleGuard(const ModuleGuard &) = delete;
      ModuleGuard &operator=(const ModuleGuard &) = delete;

    private:
      HANDLE m_process;
      DWORD64 m_base;
  };
}

std::optional<uint64_t>
SymbolDownloader::GetSymbolOffset(const std::wstring &moduleName,
                                  const std::wstring &symbolName) {
  HANDLE process = GetCurrentProcess();
  DRVLOG(L"Looking up symbol: %ls\n", symbolName.c_str());

  std::wstring moduleBaseName = moduleName;
  size_t pos = moduleBaseName.find_last_of(L"\\/");
  if (pos != std::wstring::npos) {
    moduleBaseName = moduleBaseName.substr(pos + 1);
  }

  DWORD64 baseAddr =
      SymLoadModuleExW(process, nullptr, moduleName.c_str(),
                       nullptr, 0x10000000, 0, nullptr, 0);
  if (!baseAddr) {
    DRVLOG(L"Failed to load module symbols (error: %lu)\n", GetLastError());
    return std::nullopt;
  }
  ModuleGuard unloadOnExit(process, baseAddr);

  ScopedSymbolResult scoped{symbolName.c_str(), 0, 0, false};
  if (SymEnumSymbolsW(process, baseAddr, symbolName.c_str(),
                      ScopedSymbolEnum, &scoped) &&
      scoped.found && scoped.modBase == baseAddr) {
    uint64_t offset = scoped.address - baseAddr;
    DRVLOG(L"Symbol found: %ls at offset 0x%llX\n", symbolName.c_str(), offset);
    return offset;
  }

  BYTE buffer[sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(wchar_t)];
  PSYMBOL_INFOW pSymbol = (PSYMBOL_INFOW)buffer;

  std::wstring qualified = moduleBaseName + L"!" + symbolName;
  const wchar_t *candidates[2] = {qualified.c_str(), symbolName.c_str()};

  for (const wchar_t *candidate : candidates) {
    ZeroMemory(pSymbol, sizeof(SYMBOL_INFOW));

    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFOW);
    pSymbol->MaxNameLen = MAX_SYM_NAME;

    if (!SymFromNameW(GetCurrentProcess(), candidate, pSymbol))
      continue;

    if (pSymbol->ModBase != baseAddr) {
      DRVLOG(L"Rejected %ls: resolved in foreign module (modbase 0x%llX != "
             L"0x%llX)\n",
             candidate, pSymbol->ModBase, baseAddr);
      continue;
    }

    uint64_t offset = pSymbol->Address - baseAddr;
    DRVLOG(L"Symbol found: %ls at offset 0x%llX\n", symbolName.c_str(), offset);
    return offset;
  }

  DRVLOG(L"Symbol not found in module: %ls\n", symbolName.c_str());
  return std::nullopt;
}
