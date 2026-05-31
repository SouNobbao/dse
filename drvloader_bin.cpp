unsigned char bin_patcher[] = {
#embed "bins/drvloader.exe"
	, '\0'};

unsigned int bin_patcher_len = sizeof(bin_patcher);
constexpr auto patcherEnablearg = L"restore";
constexpr auto patcherDisablearg = L"bypass";