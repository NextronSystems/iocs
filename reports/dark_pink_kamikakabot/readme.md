# DarkPink - KamiKakaBot Malware

The following IOCs are based on the analysis and research described in the following blog post

- [Unveiling KamiKakaBot - Malware Analysis](https://www.nextron-systems.com/2024/03/22/unveiling-kamikakabot-malware-analysis/)

## IOCs

#### New Variant

| Type | Indicator |
| ---- | ---- |
| Commandline | `SCHTASKS /CREATE /f /TN "OneDriver Reporting Task" /TR "shutdown /l /f" /SC WEEKLY /d TUE,FRI /ST 12:35` |
| Path | `%localappdata%\Temp\wctA91F.tmp` |
| Path | `%localappdata%\Temp\3f88dd57-6ce606be-54c358fb-c566587a.tmp` |
| C2 | `hxxps[://]api[.]telegram[.]org/bot6860236203:AAFrlFzcLuyXU4HxKisFUhvhwKucyL4rDS0` |

#### Old Variant

| Type | Indicator |
| ---- | ---- |
| Commandline | `SCHTASKS /CREATE /f /TN "Health Check" /TR "shutdown /l /f" /SC WEEKLY /d WED,FRI /ST 13:15` |
| Commandline | `SCHTASKS /CREATE /f /TN "Microsoft Idle" /TR "shutdown /l /f" /SC WEEKLY /d WED,FRI /ST 23:00` |
| Path | `%localappdata%\Temp\wctF3AB.tmp` |
| Path | `%localappdata%\Temp\207ee439-2ebd-ba42-2f6f-ea02adb4a830.tmp` |
| Path | `%localappdata%\desktop.ini.dat` |
| C2 | `hxxps[://]api[.]telegram[.]org/bot6236700491:AAEcSXSg2mYbr8ydVVlOaJXJloWVRzoMwdM` |

### Hashes

You can grab the list of all the samples we currently track related to DarkPink / KamiKakaBot from our Valhalla website

- [APT_MAL_DarkPink_KamiKakaBot_Mar24](https://valhalla.nextron-systems.com/info/rule/APT_MAL_DarkPink_KamiKakaBot_Mar24)
- [APT_MAL_DarkPink_KamiKakaBot_Stealer_Module_Mar24](https://valhalla.nextron-systems.com/info/rule/APT_MAL_DarkPink_KamiKakaBot_Stealer_Module_Mar24)
- [MAL_APT_DarkPink_DLL_Jan24](https://valhalla.nextron-systems.com/info/rule/MAL_APT_DarkPink_DLL_Jan24)

### Registry 

#### New Variant

- `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\`

    - Value: `Shell` Data: `explorer.exe, explorer.exe /e,/root,%Pyps% -nop -w h "Start-Process -N -F $env:Msbd -A $env:Temprd"`

#### Old Variant

- `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\`

    - Value: `Shell` Data: `"explorer.exe, %SYSPS% -nop -w h \"Start-Process -N -F $env:OSBuild -A $env:STMP\""`
    - Value: `Shell` Data: `"explorer.exe, %WINSYSPS% -nop -w h \"Start-Process -WindowStyle Hidden -FilePath $env:SYSS -ArgumentList $env:STMP\""`
    - Value: `Shell` Data: `"explorer.exe, explorer.exe /e,/root,%PSH% -nop -w h \"Start-Process -N -F $env:SYSB -A $env:TPM\""`
    - Value: `Shell` Data: `explorer.exe, %PSS% -nop -w h \"Start-Process -N -F $env:MS -A $env:TMPT\""`

## Additional Resources

### Sigma

- [Suspicious Environment Variable Has Been Registered](https://github.com/SigmaHQ/sigma/blob/961932ee3fa9751c8f91599b70ede33bc72d90eb/rules/windows/registry/registry_set/registry_set_suspicious_env_variables.yml)
- [Suspicious Msbuild Execution By Uncommon Parent Process](https://github.com/SigmaHQ/sigma/blob/961932ee3fa9751c8f91599b70ede33bc72d90eb/rules/windows/process_creation/proc_creation_win_msbuild_susp_parent_process.yml)
- [Scheduled Task Creation Via Schtasks.EXE](https://github.com/SigmaHQ/sigma/blob/961932ee3fa9751c8f91599b70ede33bc72d90eb/rules/windows/process_creation/proc_creation_win_schtasks_creation.yml)
- [CurrentVersion NT Autorun Keys Modification](https://github.com/SigmaHQ/sigma/blob/961932ee3fa9751c8f91599b70ede33bc72d90eb/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_currentversion_nt.yml)
- [Potential WWlib.DLL Sideloading](https://github.com/SigmaHQ/sigma/blob/961932ee3fa9751c8f91599b70ede33bc72d90eb/rules/windows/image_load/image_load_side_load_wwlib.yml)
- [Explorer Process Tree Break](https://github.com/SigmaHQ/sigma/blob/961932ee3fa9751c8f91599b70ede33bc72d90eb/rules/windows/process_creation/proc_creation_win_explorer_break_process_tree.yml)

### Scripts

- [XML Task Extractor](./scripts/XML-Task-Extractor.py)
