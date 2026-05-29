#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

bool CheckDsePipe();
void CreateDsePipe();
void CloseDsePipe();

void CreateLockFile();
void DeleteLockFile();
LPCWSTR GetLockPath();
