# dse runtime owo

How to use 

1. Add to load dll section 
2. Happy

## steam version (overlay + input)

1. Add to load dll section 
2. Remove coldclient/loader.dll
3. Use [OpenSteamTool](https://github.com/OpenSteam001/OpenSteamTool) 
4. Get these games (steam/config/lua <- lua files go here), manifests go into steamdepot/cache
5. Click Play!!!111

## linking the dll (for these launchers)

### CFF Explorer (GUI)
1. Open your exe in [CFF Explorer](https://ntcore.com/explorer-suite/)
2. Go to Import Adder
3. Click Add -> browse to `dse_loader.dll`
4. Select the available export -> click with Import by Name
5. Click Rebuild Import Table -> save the exe
6. Drop `dse.dll` next to the exe

- or just grab the launcher in releases build...


# flavours of shit code !!

| dll | what it does |
| --- | --- |
| `dse.dll` | base DSE toggle/inject helper, no Steam hooks, no console/log file |
| `dse_steam.dll` | base build + Steam hooks |
| `dse_log.dll` | base build + console + `dse-dll.log` |
| `dse_steam_log.dll` | Steam hooks + console/logging |
| `dse_all.dll` | everything above + extra paranoid stuff |
| `dse_loader.dll` | loader stub for other exes |

# what this code does
mainly drops kvc and a vbs script to elevate in temp\
once we elevate the owo stuff should not require more elevation and start the service automatically !!

# currently supported launchers
- hypervisor-launcher.exe
- steamclient_loader_x64.exe (i hope)

# stuff to fix
- [] Relaunch MSI AFTERBURNER
- [] uhh kill services (VGC, VGK, )
- [x] make sure kvc doesnt shit it self (probably done)
- [] idk you tell me
