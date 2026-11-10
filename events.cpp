#include "events.h"

#include <windows.h>

namespace {

constexpr LPCWSTR kOffFromStartEventName = L"Local\\DseDll_OffFromStart";
constexpr LPCWSTR kToggledEventName      = L"Local\\DseDll_Toggled";
constexpr LPCWSTR kAfterburnerEventName  = L"Local\\DseDll_Afterburner";

HANDLE g_hOffFromStart = nullptr;
HANDLE g_hToggled = nullptr;
HANDLE g_hAfterburner = nullptr;

HANDLE EnsureEvent(LPCWSTR name, bool initiallySignaled = false) {
	HANDLE h = OpenEventW(EVENT_ALL_ACCESS, FALSE, name);
	if (h)
		return h;

	return CreateEventW(nullptr, TRUE,
						initiallySignaled ? TRUE : FALSE, name);
}

void CloseEvent(HANDLE& h) {
	if (h) {
		CloseHandle(h);
		h = nullptr;
	}
}

}

// Dse events
bool CheckAndSetDseOffFromStart() {
	g_hOffFromStart = EnsureEvent(kOffFromStartEventName);
	return g_hOffFromStart != nullptr;
}

void SetDseOffFromStart() {
	if (!g_hOffFromStart)
		g_hOffFromStart = EnsureEvent(kOffFromStartEventName,true);
	else
		SetEvent(g_hOffFromStart);
}

bool CheckAndSetDseToggled() {
	g_hToggled = EnsureEvent(kToggledEventName);
	return g_hToggled != nullptr;
}

void SetDseToggled() {
	if (!g_hToggled)
		g_hToggled = EnsureEvent(kToggledEventName,true);
	else
		SetEvent(g_hToggled);
}

// Afterburner events
bool CheckAndSetAfterburnerEvent() {
	g_hAfterburner = EnsureEvent(kAfterburnerEventName);
	return g_hAfterburner != nullptr;
}

void SetAfterburnerEvent() {
	if (!g_hAfterburner)
		g_hAfterburner = EnsureEvent(kAfterburnerEventName, true);
	else
		SetEvent(g_hAfterburner);
}

bool WasAfterburnerEventSet() {
	return g_hAfterburner != nullptr;
}

// Lifetime / queries
void CloseGameEvents() {
	CloseEvent(g_hOffFromStart);
	CloseEvent(g_hToggled);
}

void CloseDseEvents() {
	CloseGameEvents();
	CloseEvent(g_hAfterburner);
}

bool IsOtherGameRunning() {
	HANDLE hToggled = OpenEventW(SYNCHRONIZE, FALSE, kToggledEventName);
	if (hToggled) {
		CloseHandle(hToggled);
		return true;
	}

	HANDLE hOff = OpenEventW(SYNCHRONIZE, FALSE, kOffFromStartEventName);
	if (hOff) {
		CloseHandle(hOff);
		return true;
	}

	return false;
}
