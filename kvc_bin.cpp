unsigned char bin_patcher[] = {
#embed "bins/kvc.exe"
	, '\0'};

unsigned int bin_patcher_len = sizeof(bin_patcher);
constexpr auto patcherEnablearg = L"dse on";
constexpr auto patcherDisablearg = L"dse off";
