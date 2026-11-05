#pragma once
#include "../log.h"
#include <cstdio> 
#include <cstdint>

inline void drvlog_w(const wchar_t* fmt, ...) {
    if (!g_loggingEnabled) return;
    wchar_t wbuf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = _vsnwprintf(wbuf, sizeof(wbuf) / sizeof(wbuf[0]) - 1, fmt, ap);
    wbuf[sizeof(wbuf) / sizeof(wbuf[0]) - 1] = L'\0';
    va_end(ap);
    if (n <= 0) return;
    char nbuf[2048];
    WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, nbuf, sizeof(nbuf), nullptr, nullptr);
    LOG("[drvloader] %s", nbuf);
}

#define DRVLOG(fmt, ...) drvlog_w(fmt, ##__VA_ARGS__)
