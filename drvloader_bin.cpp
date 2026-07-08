unsigned char bin_patcher[] = {
#ifndef _MSC_VER
#embed "bins/drvloader.exe"
#else
	%placeholder_drv_bin%
#endif
	, '\0'};

unsigned int bin_patcher_len = sizeof(bin_patcher);
constexpr auto patcherEnablearg = L"restore";
constexpr auto patcherDisablearg = L"bypass";



