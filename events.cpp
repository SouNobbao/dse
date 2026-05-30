#include "events.h"
#include "log.h"

static HANDLE g_hOffFromStart = nullptr;
static HANDLE g_hToggled = nullptr;
static HANDLE g_hAfterburner = nullptr;

static const LPCWSTR kOffFromStartEventName = L"Local\\DseDll_OffFromStart";
static const LPCWSTR kToggledEventName = L"Local\\DseDll_Toggled";
static const LPCWSTR kAfterburnerEventName = L"Local\\DseDll_Afterburner";

bool CheckAndSetDseOffFromStart() {
  HANDLE hEvent = OpenEventW(EVENT_ALL_ACCESS, FALSE, kOffFromStartEventName);
  if (hEvent) {
    g_hOffFromStart = hEvent;
    return true;
  }
  return false;
}

void SetDseOffFromStart() {
  if (!g_hOffFromStart) {
    g_hOffFromStart =
        CreateEventW(nullptr, TRUE, FALSE, kOffFromStartEventName);
  }
}

bool CheckAndSetDseToggled() {
  HANDLE hEvent = OpenEventW(EVENT_ALL_ACCESS, FALSE, kToggledEventName);
  if (hEvent) {
    g_hToggled = hEvent;
    return true;
  }
  return false;
}

void SetDseToggled() {
  if (!g_hToggled) {
    g_hToggled = CreateEventW(nullptr, TRUE, FALSE, kToggledEventName);
  }
}

void CloseGameEvents() {
  if (g_hOffFromStart) {
    CloseHandle(g_hOffFromStart);
    g_hOffFromStart = nullptr;
  }
  if (g_hToggled) {
    CloseHandle(g_hToggled);
    g_hToggled = nullptr;
  }
}

void CloseDseEvents() {
  CloseGameEvents();
  if (g_hAfterburner) {
    CloseHandle(g_hAfterburner);
    g_hAfterburner = nullptr;
  }
}

bool CheckAndSetAfterburnerEvent() {
  HANDLE hEvent = OpenEventW(EVENT_ALL_ACCESS, FALSE, kAfterburnerEventName);
  if (hEvent) {
    g_hAfterburner = hEvent;
    return true;
  }
  return false;
}

void SetAfterburnerEvent() {
  if (!g_hAfterburner) {
    g_hAfterburner = CreateEventW(nullptr, TRUE, FALSE, kAfterburnerEventName);
  }
}

bool WasAfterburnerEventSet() {
  return g_hAfterburner != nullptr;
}

bool IsOtherGameRunning() {
  HANDLE hToggled = OpenEventW(EVENT_ALL_ACCESS, FALSE, kToggledEventName);
  if (hToggled) {
    CloseHandle(hToggled);
    return true;
  }
  HANDLE hOffFromStart =
      OpenEventW(EVENT_ALL_ACCESS, FALSE, kOffFromStartEventName);
  if (hOffFromStart) {
    CloseHandle(hOffFromStart);
    return true;
  }
  return false;
}
