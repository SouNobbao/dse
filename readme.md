# dse

## How to use

1. Add the DLL to the load list.
2. Configure `dse.ini` as needed.

## Steam version (overlay + input)

0. Enable in config file.
1. Add the DLL to the load list.
2. Remove `coldclient/loader.dll`.
3. Use [OpenSteamTool](https://github.com/OpenSteam001/OpenSteamTool).
4. Put Lua files in `steam/config/lua` and manifests in `steamdepot/cache`.
5. Click Play.

## Linking the DLL for supported launchers

### CFF Explorer (GUI)
1. Open your exe in [CFF Explorer](https://ntcore.com/explorer-suite/)
2. Go to Import Adder.
3. Click Add and browse to `dse.dll`.
4. Select the available export and import by name.
5. Click Rebuild Import Table and save the exe.
6. Drop `dse.dll` next to the exe.

You can also use the pre-linked launchers from the release build.

## What this code does

The DLL extracts `drvloader or kvc` and a temporary VBS elevation helper, then starts the service from the elevated process.

## Currently supported launchers

- hypervisor-launcher.exe
- steamclient_loader_x64.exe

> [!NOTE]
> To add more launchers, add their configuration under `launchers.h`.

## TODO

- [x] fix afterburner.
- [ ] handle conflict between services
- [ ] check if vbs/hvci is off 
- [x] handle `kvc/drvloader` correctly.
