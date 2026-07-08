unsigned char bin_patcher[] = {
#ifndef _MSC_VER
#embed "bins/kvc.exe"
#else
	%placeholder_kvc_bin%
#endif
	, '\0'};

unsigned int bin_patcher_len = sizeof(bin_patcher);
constexpr auto patcherEnablearg = L"dse on";
constexpr auto patcherDisablearg = L"dse off";