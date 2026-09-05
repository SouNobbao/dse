# dse

## What dse does

The DLL extracts [`drvloader`](https://codeberg.org/SouNobbao/drvloader-fork) or [`kvc`](https://github.com/wesmar/kvc/releases/tag/latest) and a [temporary executable](https://codeberg.org/SouNobbao/dse/blob/master/elevator.cpp) that's compiled on this repo.

Upon opening the game, it checks if you're running under the test-signed setup or you alterady have Driver Signature Enforncement previously off. [checks are here](https://codeberg.org/sounobbao/dse/src/branch/master/checks.cpp)

Other related checks are HVCI/VBS, this tool won't turn off those, make sure you've disabled them before running.

Upon opening it disables dse and hooks over to CreateWindowExW, ensuring that the program is opened before turning dse back on.

`CreateProcess`/`CreateProcessWithTokenW` are only hooked to load dse.dll for that game in case of a launcher.

## How to use

1. Add the DLL to the load list (`reflex.ini`, `xxxowo.ini`) example setups.
    ### Example setups
    ```
    reflex.ini
    [load_dlls]
    0=dse.dll
    ```

    ```
    xxxowo.ini
    [LoadDlls]
    0=dse.dll
    ```
2. Configure `dse.ini` if needed.

## Steam config setup (overlay + input)
### CAP/2k games wont get support, please only use dse option with these titles.

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

### In cases where the game only works with coldclient setups (SCDLC)
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

## Currently supported launchers

- hypervisor-launcher.exe
- steamclient_loader_x64.exe

> [!NOTE]
> To add more launchers, add their configuration under `launchers.h`.

## Disclaimer 

You, as the user, you're responsible for any misuse of this software. The authors condone the use of this software for any malicious purposes.

### Issues

Before submitting any issues please make sure following:
- you are sure that the dll was loaded
- there is not any issue after trying [drvloader](https://github.com/SouNobbao/drvloader-fork/releases/latest) manually
- where this dll was used, and how it was loaded (e.g. from a launcher, from another dll or linked)
- you are sure that you don't have external programs interfering with dse.dll (e.g. MSI Afterburner, Rivatuner, Anti-Cheat Systems), and if they were, you are sure that `dse.dll` closed the interfering programs.
- you are sure that `dse.ini` is correctly configured, for your use case.
- you are sure that there is not any issue with the game or launcher (e.g. corrupt game files, outdated launcher)
- you are sure that the launcher is not renamed and corresponds to [launchers.h](https://codeberg.org/sounobbao/dse/src/branch/master/launchers.h#L17-L22)
- you've read the readme

If all above are true, and you still have issues, please submit an issue with all the information requested above and make sure that `logging=true` is enabled on `dse.ini` and you attach the log file

### External Programs

The files provided in `extras` come from the following places

- pe_reader > [LIEF](https://github.com/lief-project/LIEF)
- steamclient_loader_x64.exe > [gbe_fork](https://github.com/Detanup01/gbe_fork/)
- hypervisor-launcher.exe > [hypervisor-launcher](https://git.denuvosanctuary.com/andreh/hypervisor-launcher/)