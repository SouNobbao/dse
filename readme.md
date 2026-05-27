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

# flavours of shit code !!

| dll | what it does |
| --- | --- |
| `dse.dll` | base DSE toggle/inject helper, no Steam hooks, no console/log file |
| `dse_steam.dll` | base build + Steam hooks |
| `dse_log.dll` | base build + console + `dse-dll.log` |
| `dse_steam_log.dll` | Steam hooks + console/logging |
| `dse_all.dll` | everything above + extra paranoid stuff |

# what this code does
mainly drops kvc and a vbs script to elevate in temp \ 
once we elevate the owo stuff should not require more elevation and start the service automatically !!

# stuff to fix
- [] Relaunch MSI AFTERBURNER
- [] uhh kill services
- [] idk you tell me
