#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

void CreateDseOffFromStartLock();
void DeleteDseOffFromStartLock();
bool DseWasOffFromStart();

void CreateDseToggledLock();
void DeleteDseToggledLock();
bool DseWasToggled();
