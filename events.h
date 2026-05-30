#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

bool CheckAndSetDseOffFromStart();
void SetDseOffFromStart();

bool CheckAndSetDseToggled();
void SetDseToggled();

void CloseDseEvents();
bool IsOtherGameRunning();

