# Katz Stealer Threat Analysis

The following IOCs are based on the analysis and research described in the following blog post

- [Katz Stealer Threat Analysis](https://www.nextron-systems.com/2025/05/23/katz-stealer-threat-analysis/)
## IOCs


**C2 Addresses:**
```
185.107.74.40
31.177.109.39
twist2katz[.]com
pub-ce02802067934e0eb072f69bf6427bf6.r2.dev
```

**Related Domains:**
```
katz-stealer[.]com
katzstealer[.]com
```

**User-Agent:**
```
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 katz-ontop
```

**Filenames:**
```
\AppData\Local\Temp\katz_ontop.dll
\AppData\Local\Temp\received_dll.dll
\AppData\Roaming\decrypted_chrome_key.txt
\AppData\Roaming\decrypted_brave_key.txt
\AppData\Roaming\decrypted_edge_key.txt
```

**Payloads:**
| File | SHA256 |
| --- | --- |
| Gzip Archive | 22af84327cb8ecafa44b51e9499238ca2798cec38c2076b702c60c72505329cb |
| JS Script | e4249cf9557799e8123e0b21b6a4be5ab8b67d56dc5bfad34a1d4e76f7fd2b19 |
| PowerShell script | fb2b9163e8edf104b603030cff2dc62fe23d8f158dd90ea483642fce2ceda027 |
| .NET Payload | 0df13fd42fb4a4374981474ea87895a3830eddcc7f3bd494e76acd604c4004f7 |
| .NET UAC Bypass | 4f12c5dca2099492d0c0cd22edef841cbe8360af9be2d8e9b57c2f83d401c1a7 |
| katz_ontop.dll | 6dc8e99da68b703e86fa90a8794add87614f254f804a8d5d65927e0676107a9d |
| katz_ontop.dll | e73f6e1f6c28469e14a88a633aef1bc502d2dbb1d4d2dfcaaef7409b8ce6dc99 |
| received_dll.dll | 15953e0191edaa246045dda0d7489b3832f27fdc3fcc5027f26b89692aefd6e1 |
| Stealer Payload | 2798bf4fd8e2bc591f656fa107bd871451574d543882ddec3020417964d2faa9 |
| Stealer Payload | e345d793477abbecc2c455c8c76a925c0dfe99ec4c65b7c353e8a8c8b14da2b6 |
| Stealer Payload | c601721933d11254ae329b05882337db1069f81e4d04cd4550c4b4b4fe35f9cd |
| Stealer Payload | fdc86a5b3d7df37a72c3272836f743747c47bfbc538f05af9ecf78547fa2e789 |
| Stealer Payload | 25b1ec4d62c67bd51b43de181e0f7d1bda389345b8c290e35f93ccb444a2cf7a |
| Stealer Payload | 964ec70fc2fdf23f928f78c8af63ce50aff058b05787e43c034e04ea6cbe30ef |
| Stealer Payload | d92bb6e47cb0a0bdbb51403528ccfe643a9329476af53b5a729f04a4d2139647 |
| Stealer Payload | b249814a74dff9316dc29b670e1d8ed80eb941b507e206ca0dfdc4ff033b1c1f |
| Stealer Payload | 925e6375deaa38d978e00a73f9353a9d0df81f023ab85cf9a1dc046e403830a8 |
| Stealer Payload | 96ada593d54949707437fa39628960b1c5d142a5b1cb371339acc8f86dbc7678 |
| Stealer Payload | b912f06cf65233b9767953ccf4e60a1a7c262ae54506b311c65f411db6f70128 |
| Stealer Payload | 2852770f459c0c6a0ecfc450b29201bd348a55fb3a7a5ecdcc9986127fdb786b |
| Stealer Payload | 5dd629b610aee4ed7777e81fc5135d20f59e43b5d9cc55cdad291fcf4b9d20eb |

## Additional Resources

### Sigma Rules

| Description| Rule |
|---|---|
| Detects the use of cmstp.exe to bypass UAC | [proc_creation_win_uac_bypass_cmstp](https:////github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_uac_bypass_cmstp.yml) |
| Detects suspicious execution of 'Msbuild.exe' by a uncommon parent process | [proc_creation_win_msbuild_susp_parent_process](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_msbuild_susp_parent_process.yml) |
| Detects processes that query known 3rd party registry keys that hold credentials via commandline | [proc_creation_win_registry_enumeration_for_credentials_cli](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_registry_enumeration_for_credentials_cli.yml) |
| Detects execution of Chromium based browser in headless mode | [proc_creation_win_browsers_chromium_headless_exec](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_browsers_chromium_headless_exec.yml)|
