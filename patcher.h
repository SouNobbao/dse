#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

bool IsRunningAsAdmin();
bool IsDseEnabled(bool defaultVal = true);
void DisableDse();
void EnableDse();
