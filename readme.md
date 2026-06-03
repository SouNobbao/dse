# dse

## How to use

1. Add the DLL to the load list.
2. Configure `dse.ini` as needed.

## Steam version (overlay + input)

1. Enable in config (`dse.ini`) file `steamHooks=1/true/yes`.
    ```ini
    [dse]
    ; Automatically toggle DSE. If DSE was already disabled
    ; patcher will not run.
    toggleDse=true

    ; Enable/disable Steam API hooks
    steamHooks=true

    ; Enable coldloader support (for games that need it)
    coldloaderhooks=false
    steam_path=<YOUR_STEAM_PATH>

    ; Enable/disable logging output
    logging=false

    ; Its dependent on toggleDse
    ; Problematic services to stop or delete (Format: ServiceName:ACTION)
    ; STOP - just stops the service, and relaunches once game ends
    ; DELETE - deletes the service, and does not relaunch
    problematic_services=vgk:STOP, vgc:STOP, FACEIT:DELETE

    ; Problematic tasks to kill (comma separated executable names, these are not relaunched)
    problematic_tasks=vgtray.exe,
    ```
2. Add the DLL to the load list.
3. Remove `coldclient/loader.dll`.
4. Use [OpenSteamTool](https://github.com/OpenSteam001/OpenSteamTool).
5. Put Lua files in `steam/config/lua` and manifests in `steamdepot/cache`.
6. Click Play.

## In case the game likes the emulator a bit much

1. Enable in config (`dse.ini`) file `steamHooks=1/true/yes` and `coldloaderhooks=1/true/yes`

    1.1 Make sure that `steam_path` is set to your steam path, and you have `coldclient` near dse.dll or exe
    ```ini
    [dse]
    ; Automatically toggle DSE. If DSE was already disabled
    ; patcher will not run.
    toggleDse=true

    ; Enable/disable Steam API hooks
    steamHooks=true

    ; Enable coldloader support (for games that need it)
    coldloaderhooks=true
    steam_path=<YOUR_STEAM_PATH>

    ; Enable/disable logging output
    logging=true

    ; Its dependent on toggleDse
    ; Problematic services to stop or delete (Format: ServiceName:ACTION)
    ; STOP - just stops the service, and relaunches once game ends
    ; DELETE - deletes the service, and does not relaunch
    problematic_services=vgk:STOP, vgc:STOP, FACEIT:DELETE

    ; Problematic tasks to kill (comma separated executable names, these are not relaunched)
    problematic_tasks=vgtray.exe,
    ```
2. Make sure that coldclient/loader is always loaded before `dse.dll`
    Example `someone.ini`
    ```ini
    [LoadDlls]
    0=coldclient\coldloader.dll
    1=coldclient\dse.dll
    ```

    > [!NOTE]
    > This creates a hardlink (copy if it fails) of `steamclient64.dll` named `steamclient64_valve.dll` in your steam folder

3. Use [OpenSteamTool](https://github.com/OpenSteam001/OpenSteamTool).
4. Put Lua files in `steam/config/lua` and manifests in `steamdepot/cache`.
5. Click Play.

## Linking the DLL for launchers or without loaders

### CFF Explorer (GUI)
1. Open your exe/dll in [CFF Explorer](https://ntcore.com/explorer-suite/)
2. Go to Import Adder.
3. Click Add and browse to `dse.dll`.
4. Select the export `DseDll` and import by name.
5. Click Rebuild Import Table and save the exe or dll.
6. Drop `dse.dll` next to the exe/dll.

### PEFile (TUI)

1. `pe_reader.exe` is used to check which dlls are linked on the exe
2. Download `pefile.exe` in releases
3. Run pefile.exe with the correct arguments
4. Command Example
    > `pefile.exe example.exe/dll dse.dll DseDll`
5. Get the example_mod.exe/dll file
6. Rename to example.exe/dll

You can also use the pre-linked launchers from the release build.

## What this code does

The DLL extracts `drvloader or kvc` and a temporary elevation helper.

## Currently supported launchers

- hypervisor-launcher.exe
- steamclient_loader_x64.exe

> [!NOTE]
> To add more launchers, add their configuration under `launchers.h`.