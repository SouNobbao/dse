#include "events.h"
#include "log.h"

static HANDLE g_hOffFromStart = nullptr;
static HANDLE g_hToggled = nullptr;

static const LPCWSTR kOffFromStartEventName = L"Local\\DseDll_OffFromStart";
static const LPCWSTR kToggledEventName = L"Local\\DseDll_Toggled";

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

void CloseDseEvents() {
  if (g_hOffFromStart) {
    CloseHandle(g_hOffFromStart);
    g_hOffFromStart = nullptr;
  }
  if (g_hToggled) {
    CloseHandle(g_hToggled);
    g_hToggled = nullptr;
  }
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
