#include "ConfigManager.h"
#include "drvlog.h"
#include "../common.h"
#include <vector>
#include <algorithm>
#include <sstream>
#include <winreg.h>
#include <shlobj.h>
#include <shlwapi.h>

#pragma comment(lib, "shell32.lib")

namespace ConfigManager {

std::wstring GetDriversIniPath() {
    WCHAR path[MAX_PATH]{};
    GetDseTempPath(L"drivers.ini", path);
    return path;
}

std::wstring GetDriverPath() {
    WCHAR path[MAX_PATH]{};
    GetDseTempPath(L"RTCore64.sys", path);
    return path;
}

bool UpdateDriversIni(uint64_t seCiCallbacks, uint64_t safeFunction) {
    std::wstring filePath = GetDriversIniPath();

    if (GetFileAttributesW(filePath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        DRVLOG(L"drivers.ini not found... skipping file update\n");
        return false;
    }

    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hFile == INVALID_HANDLE_VALUE) {
        DRVLOG(L"Failed to open drivers.ini for reading\n");
        return false;
    }

    DWORD fileSize = GetFileSize(hFile, nullptr);
    if (fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return false;
    }

    std::vector<BYTE> buffer(fileSize);
    DWORD bytesRead = 0;

    if (!ReadFile(hFile, buffer.data(), fileSize, &bytesRead, nullptr)) {
        CloseHandle(hFile);
        return false;
    }

    CloseHandle(hFile);

    std::wstring content;
    if (fileSize >= 2 && buffer[0] == 0xFF && buffer[1] == 0xFE) {
        content = std::wstring((wchar_t*)(buffer.data() + 2), (fileSize - 2) / sizeof(wchar_t));
    } else {
        content = std::wstring((wchar_t*)buffer.data(), fileSize / sizeof(wchar_t));
    }

    size_t configPos = content.find(L"[Config]");
    if (configPos == std::wstring::npos) return false;

    size_t nextSection = content.find(L"\n[", configPos + 1);
    size_t sectionEnd = (nextSection != std::wstring::npos) ? nextSection : content.length();

    size_t anchorPos = content.find(L"IoControlCode_Write=", configPos);
    if (anchorPos == std::wstring::npos || anchorPos >= sectionEnd) return false;

    size_t anchorLineEnd = content.find(L'\n', anchorPos);
    if (anchorLineEnd == std::wstring::npos || anchorLineEnd > sectionEnd)
        anchorLineEnd = sectionEnd;

    std::wstringstream expectedSeCi;
    expectedSeCi << L"Offset_SeCiCallbacks=0x" << std::hex << std::uppercase << seCiCallbacks
                 << L"     ; g_CiCallbacks structure base (static offset in ntoskrnl)";

    std::wstringstream expectedSafe;
    expectedSafe << L"Offset_SafeFunction=0x" << std::hex << std::uppercase << safeFunction
                 << L"      ; ZwFlushInstructionCache - always-success dummy function";

    bool seCiNeedsUpdate = true;
    bool safeNeedsUpdate = true;

    size_t seCiPos = content.find(L"Offset_SeCiCallbacks=", configPos);
    if (seCiPos != std::wstring::npos && seCiPos < sectionEnd) {
        size_t lineEnd = content.find(L'\n', seCiPos);
        if (lineEnd == std::wstring::npos || lineEnd > sectionEnd) lineEnd = sectionEnd;
        std::wstring currentLine = content.substr(seCiPos, lineEnd - seCiPos);
        if (currentLine == expectedSeCi.str()) seCiNeedsUpdate = false;
    }

    size_t safePos = content.find(L"Offset_SafeFunction=", configPos);
    if (safePos != std::wstring::npos && safePos < sectionEnd) {
        size_t lineEnd = content.find(L'\n', safePos);
        if (lineEnd == std::wstring::npos || lineEnd > sectionEnd) lineEnd = sectionEnd;
        std::wstring currentLine = content.substr(safePos, lineEnd - safePos);
        if (currentLine == expectedSafe.str()) safeNeedsUpdate = false;
    }

    if (!seCiNeedsUpdate && !safeNeedsUpdate) {
        DRVLOG(L"drivers.ini already has correct offsets\n");
        return true;
    }

    if (seCiNeedsUpdate) {
        seCiPos = content.find(L"Offset_SeCiCallbacks=", configPos);
        if (seCiPos != std::wstring::npos && seCiPos < sectionEnd) {
            size_t lineEnd = content.find(L'\n', seCiPos);
            if (lineEnd == std::wstring::npos || lineEnd > sectionEnd) lineEnd = sectionEnd;
            content.replace(seCiPos, lineEnd - seCiPos, expectedSeCi.str());
            nextSection = content.find(L"\n[", configPos + 1);
            sectionEnd = (nextSection != std::wstring::npos) ? nextSection : content.length();
        } else {
            std::wstring newLine = L"\n" + expectedSeCi.str();
            content.insert(anchorLineEnd, newLine);
            nextSection = content.find(L"\n[", configPos + 1);
            sectionEnd = (nextSection != std::wstring::npos) ? nextSection : content.length();
        }
    }

    if (safeNeedsUpdate) {
        safePos = content.find(L"Offset_SafeFunction=", configPos);
        if (safePos != std::wstring::npos && safePos < sectionEnd) {
            size_t lineEnd = content.find(L'\n', safePos);
            if (lineEnd == std::wstring::npos || lineEnd > sectionEnd) lineEnd = sectionEnd;
            content.replace(safePos, lineEnd - safePos, expectedSafe.str());
        } else {
            anchorPos = content.find(L"IoControlCode_Write=", configPos);
            anchorLineEnd = content.find(L'\n', anchorPos);
            if (anchorLineEnd == std::wstring::npos) {
                nextSection = content.find(L"\n[", configPos + 1);
                anchorLineEnd = (nextSection != std::wstring::npos) ? nextSection : content.length();
            }
            std::wstring newLine = L"\n" + expectedSafe.str();
            content.insert(anchorLineEnd, newLine);
        }
    }

    hFile = CreateFileW(filePath.c_str(), GENERIC_WRITE, 0,
        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hFile == INVALID_HANDLE_VALUE) {
        DRVLOG(L"Failed to open drivers.ini for writing\n");
        return false;
    }

    BYTE bom[2] = { 0xFF, 0xFE };
    DWORD bytesWritten = 0;
    WriteFile(hFile, bom, 2, &bytesWritten, nullptr);

    DWORD contentSize = (DWORD)(content.length() * sizeof(wchar_t));
    if (!WriteFile(hFile, content.c_str(), contentSize, &bytesWritten, nullptr)) {
        CloseHandle(hFile);
        return false;
    }

    CloseHandle(hFile);
    DRVLOG(L"Updated drivers.ini with current offsets\n");
    return true;
}

bool SaveOffsetsToRegistry(uint64_t seCiCallbacks, uint64_t safeFunction, const std::wstring& buildInfo) {
    HKEY hKey;

    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t timestamp[32];
    swprintf_s(timestamp, L"%04d%02d%02d_%02d%02d%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    std::wstring historyPath = L"Software\\drvloader\\History\\";
    historyPath += timestamp;

    LSTATUS result = RegCreateKeyExW(HKEY_CURRENT_USER, historyPath.c_str(), 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr);

    if (result != ERROR_SUCCESS) return false;

    wchar_t timestampStr[64];
    swprintf_s(timestampStr, L"%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    RegSetValueExW(hKey, L"Timestamp", 0, REG_SZ, (BYTE*)timestampStr,
        (DWORD)((wcslen(timestampStr) + 1) * sizeof(wchar_t)));

    DWORD seCiDword = (DWORD)seCiCallbacks;
    RegSetValueExW(hKey, L"SeCiCallbacks", 0, REG_DWORD, (BYTE*)&seCiDword, sizeof(DWORD));

    DWORD safeDword = (DWORD)safeFunction;
    RegSetValueExW(hKey, L"SafeFunction", 0, REG_DWORD, (BYTE*)&safeDword, sizeof(DWORD));

    RegSetValueExW(hKey, L"BuildInfo", 0, REG_SZ, (BYTE*)buildInfo.c_str(),
        (DWORD)((buildInfo.length() + 1) * sizeof(wchar_t)));

    RegCloseKey(hKey);

    // Keep only the last 8 history entries
    HKEY hHistoryKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\drvloader\\History", 0,
        KEY_READ | KEY_WRITE, &hHistoryKey) == ERROR_SUCCESS) {

        std::vector<std::wstring> entries;
        wchar_t subKeyName[256];
        DWORD index = 0;

        while (RegEnumKeyW(hHistoryKey, index++, subKeyName, 256) == ERROR_SUCCESS) {
            entries.push_back(subKeyName);
        }

        if (entries.size() > 8) {
            std::sort(entries.begin(), entries.end());
            for (size_t i = 0; i < entries.size() - 8; i++) {
                RegDeleteTreeW(hHistoryKey, entries[i].c_str());
            }
        }

        RegCloseKey(hHistoryKey);
    }

    return true;
}

bool SaveOriginalCallbackToRegistry(uint64_t callback) {
    HKEY hKey;

    LSTATUS result = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\drvloader\\LatestState", 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr);

    if (result != ERROR_SUCCESS) return false;

    RegSetValueExW(hKey, L"OriginalCallback", 0, REG_QWORD, (BYTE*)&callback, sizeof(uint64_t));

    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t timestampStr[64];
    swprintf_s(timestampStr, L"%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    RegSetValueExW(hKey, L"PatchTimestamp", 0, REG_SZ, (BYTE*)timestampStr,
        (DWORD)((wcslen(timestampStr) + 1) * sizeof(wchar_t)));

    DWORD isPatched = 1;
    RegSetValueExW(hKey, L"IsPatched", 0, REG_DWORD, (BYTE*)&isPatched, sizeof(DWORD));

    RegCloseKey(hKey);
    DRVLOG(L"Saved original callback to registry: 0x%llX\n", callback);
    return true;
}

std::optional<uint64_t> LoadOriginalCallbackFromRegistry() {
    HKEY hKey;

    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\drvloader\\LatestState", 0,
        KEY_READ, &hKey) != ERROR_SUCCESS) {
        return std::nullopt;
    }

    uint64_t callback = 0;
    DWORD dataSize = sizeof(uint64_t);

    if (RegQueryValueExW(hKey, L"OriginalCallback", nullptr, nullptr,
        (BYTE*)&callback, &dataSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return std::nullopt;
    }

    RegCloseKey(hKey);
    DRVLOG(L"Loaded OriginalCallback from registry: 0x%llX\n", callback);
    return callback;
}

bool ClearPatchStateFromRegistry() {
    HKEY hKey;

    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\drvloader\\LatestState", 0,
        KEY_WRITE, &hKey) != ERROR_SUCCESS) {
        return false;
    }

    RegDeleteValueW(hKey, L"OriginalCallback");
    RegDeleteValueW(hKey, L"OriginalCiOptions");
    RegDeleteValueW(hKey, L"PatchTimestamp");

    DWORD isPatched = 0;
    RegSetValueExW(hKey, L"IsPatched", 0, REG_DWORD, (BYTE*)&isPatched, sizeof(DWORD));

    RegCloseKey(hKey);
    DRVLOG(L"Cleared patch state from registry\n");
    return true;
}

bool SaveOriginalCiOptionsToRegistry(uint32_t value) {
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\drvloader\\LatestState", 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr) != ERROR_SUCCESS)
        return false;

    RegSetValueExW(hKey, L"OriginalCiOptions", 0, REG_DWORD, (BYTE*)&value, sizeof(DWORD));

    DWORD isPatched = 1;
    RegSetValueExW(hKey, L"IsPatched", 0, REG_DWORD, (BYTE*)&isPatched, sizeof(DWORD));

    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t ts[64];
    swprintf_s(ts, L"%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    RegSetValueExW(hKey, L"PatchTimestamp", 0, REG_SZ, (BYTE*)ts,
        (DWORD)((wcslen(ts) + 1) * sizeof(wchar_t)));

    RegCloseKey(hKey);
    DRVLOG(L"Saved OriginalCiOptions to registry: 0x%08X\n", value);
    return true;
}

std::optional<uint32_t> LoadOriginalCiOptionsFromRegistry() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\drvloader\\LatestState", 0,
        KEY_READ, &hKey) != ERROR_SUCCESS)
        return std::nullopt;

    DWORD val = 0, size = sizeof(val);
    if (RegQueryValueExW(hKey, L"OriginalCiOptions", nullptr, nullptr,
        (BYTE*)&val, &size) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return std::nullopt;
    }

    RegCloseKey(hKey);
    return val;
}

bool IsPatchedFromRegistry() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\drvloader\\LatestState", 0,
        KEY_READ, &hKey) != ERROR_SUCCESS)
        return false;

    DWORD val = 0, size = sizeof(val);
    bool patched = RegQueryValueExW(hKey, L"IsPatched", nullptr, nullptr,
        (BYTE*)&val, &size) == ERROR_SUCCESS && val != 0;
    RegCloseKey(hKey);
    return patched;
}

std::wstring GetWindowsBuildNumber() {
    WCHAR systemRoot[MAX_PATH];
    GetSystemDirectoryW(systemRoot, MAX_PATH);
    std::wstring ntoskrnlPath = std::wstring(systemRoot) + L"\\ntoskrnl.exe";

    DWORD verHandle = 0;
    DWORD verSize = GetFileVersionInfoSizeW(ntoskrnlPath.c_str(), &verHandle);
    if (verSize == 0) return L"Unknown";

    std::vector<BYTE> verData(verSize);
    if (!GetFileVersionInfoW(ntoskrnlPath.c_str(), 0, verSize, verData.data())) {
        return L"Unknown";
    }

    VS_FIXEDFILEINFO* pFileInfo = nullptr;
    UINT len = 0;
    if (!VerQueryValueW(verData.data(), L"\\", (LPVOID*)&pFileInfo, &len)) {
        return L"Unknown";
    }

    wchar_t buildNumber[64];
    swprintf_s(buildNumber, L"%d.%d.%d.%d",
        HIWORD(pFileInfo->dwFileVersionMS),
        LOWORD(pFileInfo->dwFileVersionMS),
        HIWORD(pFileInfo->dwFileVersionLS),
        LOWORD(pFileInfo->dwFileVersionLS));

    return buildNumber;
}

} // namespace ConfigManager
