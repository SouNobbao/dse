# dse

## How to use

1. Add the DLL to the load list.
2. Configure `dse.ini` as needed.

## Steam version (overlay + input)

1. Enable in config file.
2. Add the DLL to the load list.
3. Remove `coldclient/loader.dll`.
4. Use [OpenSteamTool](https://github.com/OpenSteam001/OpenSteamTool).
5. Put Lua files in `steam/config/lua` and manifests in `steamdepot/cache`.
6. Click Play.

## Linking the DLL for supported launchers

### CFF Explorer (GUI)
1. Open your exe in [CFF Explorer](https://ntcore.com/explorer-suite/)
2. Go to Import Adder.
3. Click Add and browse to `dse.dll`.
4. Select the available export and import by name.
5. Click Rebuild Import Table and save the exe.
6. Drop `dse.dll` next to the exe.

### PEFile (TUI)

1. `pe_reader.exe` is used to check which dlls are linked on the exe
2. Download `pefile.exe` in releases
3. Run pefile.exe with the correct arguments
4. Command Example
    > `pefile.exe example.dll dse.dll DseDll`
5. Get the example_mod.dll file
6. Rename to example.dll

You can also use the pre-linked launchers from the release build.

## What this code does

The DLL extracts `drvloader or kvc` and a temporary VBS elevation helper, then starts the service from the elevated process.

## Currently supported launchers

- hypervisor-launcher.exe
- steamclient_loader_x64.exe

> [!NOTE]
> To add more launchers, add their configuration under `launchers.h`.