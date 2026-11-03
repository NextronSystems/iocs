# Gorbag: Russia-Aligned Espionage Targeting Ukrainian Frontline Institutions

In November 2026, [ESET Research published a report](https://www.welivesecurity.com/en/eset-research/gorbag-orcs-border-harvesting-intelligence-ukraine/) on a Russia-aligned threat actor they named **Gorbag**, active since at least February 2025. Gorbag targets Ukrainian law enforcement, justice, defense, and local administrations near the front line, using spearphishing emails and weaponized RAR archives that exploit the WinRAR path traversal vulnerability [CVE-2025-8088](https://nvd.nist.gov/vuln/detail/CVE-2025-8088) (discovered by ESET).

The group deploys two main tools:

- **BeautyStealer** — a C++ browser-data and file stealer (versions 0.9 through 2.0) that exfiltrates to Telegram or a FastAPI C&C server
- **Prime ReverseShell** — a PowerShell reverse shell packaged inside a .NET binary via PS2EXE, derived from a public [PSSW100AVB](https://github.com/PSSW100AVB) repository

## Nextron Rule Coverage

Our pre-existing generic YARA rules detected these samples the moment they were first submitted to VirusTotal — months before this threat analysis was published. The rules were written in 2021 and triggered on behavioral patterns common to this type of malware, not on Gorbag-specific indicators.

| YARA Rule | What It Detects | Stage |
|---|---|---|
| [SUSP_Stealer_Indicators_Oct22_1](https://valhalla.nextron-systems.com/info/rule/SUSP_Stealer_Indicators_Oct22_1) | Indicators commonly found in stealer samples | BeautyStealer binary |
| [MAL_GiftedCRook_Stealer_Apr25](https://valhalla.nextron-systems.com/info/rule/MAL_GiftedCRook_Stealer_Apr25) | GiftedCRook stealer family (shares code lineage with BeautyStealer) | BeautyStealer binary |
| [SUSP_PS2EXE_PowerShell2Exe_2](https://valhalla.nextron-systems.com/info/rule/SUSP_PS2EXE_PowerShell2Exe_2) | Compiled and unsigned PowerShell scripts (PS2EXE) | Prime ReverseShell (.NET/PS2EXE wrapper) |
| [SUSP_RAR_NTFS_ADS](https://valhalla.nextron-systems.com/info/rule/SUSP_RAR_NTFS_ADS) | RAR archives with NTFS alternate data streams — the technique Gorbag uses to exploit CVE-2025-8088 | Weaponized RAR archive |
| [SUSP_LNK_SuspiciousCommands](https://valhalla.nextron-systems.com/info/rule/SUSP_LNK_SuspiciousCommands) | LNK files containing suspicious command-line content | Malicious LNK shortcut (persistence) |
| [SUSP_LNK_ScriptContent_Apr21_1](https://valhalla.nextron-systems.com/info/rule/SUSP_LNK_ScriptContent_Apr21_1) | LNK files with embedded script command lines | Malicious LNK shortcut (persistence) |
| [SUSP_SCRIPT_PowerShell_Param_Abbrev_Jul21](https://valhalla.nextron-systems.com/info/rule/SUSP_SCRIPT_PowerShell_Param_Abbrev_Jul21) | Suspicious use of abbreviated PowerShell parameters | PowerShell loader stage |

### Timeline

Our rules detected every stage of the Gorbag toolchain from the moment each sample first appeared on VirusTotal:

- **2025-07-16** — BeautyStealer flagged by `SUSP_Stealer_Indicators_Oct22_1` and `MAL_GiftedCRook_Stealer_Apr25` on first submission
- **2025-09-26** — Prime ReverseShell flagged by `SUSP_PS2EXE_PowerShell2Exe_2` on first submission
- **2026-02-04** — Earliest weaponized LNK flagged by `SUSP_SCRIPT_PowerShell_Param_Abbrev_Jul21`, one day after first submission (2026-02-03)
- **2026-06-07** — Weaponized RAR archive flagged by `SUSP_RAR_NTFS_ADS`
- **2026-06-26** — Bulk of LNK samples flagged by all three LNK/PowerShell rules on the same day they first appeared

These are generic behavioral rules, not indicators written after the fact. `SUSP_LNK_ScriptContent_Apr21_1` was created in **April 2021**, `SUSP_Stealer_Indicators_Oct22_1` in **October 2022**, and `SUSP_PS2EXE_PowerShell2Exe_2` targets a known red-team technique — all years before Gorbag's first known operation in February 2025.

## Indicators of Compromise

### Files

#### Weaponized RAR Archives (CVE-2025-8088)

| SHA-256 | Description |
|---|---|
| `583754e5e682ea83d58fbf76ea5c82ea0f2ab5db06e9e52343c4d52f35f0a4a6` | RAR archive exploiting CVE-2025-8088 with NTFS ADS |

#### Spearphishing Lure Documents

| SHA-256 | Description |
|---|---|
| `bc77054ea7d262fcccde9d6f1df122c1b700b0699679217d1b15ea6570ec3f2c` | Spearphishing email |
| `9ce0f41d6e575aca81d290b3d0b89b011da4f9b87276b27d1c7de81695d4c927` | Macro-enabled XLS lure dropping BeautyStealer |

#### Malicious LNK Files (Persistence via Startup Folder)

| SHA-256 | Filename | First Seen |
|---|---|---|
| `24520d4654a04a4605a9ce84341bf35ec2072a1e7f669bc0212f22783ff49565` | — | 2026-02-03 |
| `35de98f9e0d48125965d57480e6477118eb0050502bbdb764166ffa2c1e3a626` | Відомості з реєстру військовозобов'язаних... | 2026-06-26 |
| `05e131555faabae0960f0527cfb72d2b8e2381fd0fde22b0b4e2b365c7faf445` | взвод розвідки.pdf... | 2026-06-26 |
| `0a9bc91e7ea2c3931f662eea37c00c7c26c8996b65f6f7afe6cce8f6114f94b6` | — | 2026-06-26 |
| `39dd1bd3bccc314d8933e5c41ed2ab084e4e20af569f77b7cf09abc5855b9483` | — | 2026-06-26 |
| `1ebbdf3671cd5ca25a8a8e7ca2f6e46dd22c631e01bfcc5c909ae2fd680bf458` | — | 2026-06-26 |
| `f668bd551859007cf2cc2a62bf0bf5414870a04e9782590c9bf85c849ddb308b` | — | 2026-06-26 |
| `1c170b7470d507378ddb78e9d66305f1184e965baaf2d27ededb23a318a58953` | — | 2026-06-30 |
| `bf338d88f60c0d352cd0d1b5e4bc6a1d9f1ac8fe1df48516ec0042cafda821e9` | — | 2026-06-26 |
| `507b2fcdae058cebbd550965b90c44e878d7a2463058c846eeb68f0dc1b48eda` | — | 2026-06-26 |
| `f9d2907d6b1de3078a0f111cc98764a92baf5ebd06cc8ab02637a65eff3b7f3a` | — | 2026-06-26 |

### Network

| Indicator | Description |
|---|---|
| `89.44.9[.]186` | Prime ReverseShell C&C (M247 Europe SRL) |
| `142.111.194[.]73` | BeautyStealer exfiltration server (EGIHosting) |

### Host

| Indicator | Description |
|---|---|
| `C:\ProgramData\W8d` | PowerShell loader on disk |
| `C:\ProgramData\SNLk` | Encrypted payload on disk |
| `C:\ProgramData\WC3` | PowerShell loader variant |
| `%AppData%\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk` | Persistence via Startup folder (random LNK names) |

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Phishing: Spearphishing Attachment | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Macro-enabled XLSM lure documents |
| Exploitation for Client Execution | [T1203](https://attack.mitre.org/techniques/T1203/) | CVE-2025-8088 WinRAR path traversal |
| User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Victim opens weaponized RAR or XLSM |
| Boot or Logon Autostart Execution: Startup Folder | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | LNK files dropped into Windows Startup |
| Command and Scripting Interpreter: PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell loaders and Prime ReverseShell |
| Obfuscated Files or Information | [T1027](https://attack.mitre.org/techniques/T1027/) | Encrypted payloads on disk |
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | BeautyStealer exfiltration via Telegram API and FastAPI C&C |
| Credentials from Password Stores: Credentials from Web Browsers | [T1555.003](https://attack.mitre.org/techniques/T1555/003/) | BeautyStealer harvests browser credentials and cookies |
| Data from Local System | [T1005](https://attack.mitre.org/techniques/T1005/) | BeautyStealer collects documents from the local file system |
| Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) | Stolen data sent to C&C or Telegram |

## References

- [ESET Research: Gorbag — Orcs at the border harvesting intelligence from Ukraine](https://www.welivesecurity.com/en/eset-research/gorbag-orcs-border-harvesting-intelligence-ukraine/) (November 2026)
- [Virus Bulletin 2026 conference paper](https://www.virusbulletin.com/conference/vb2026/) by Damien Schaeffer (ESET)
- [CVE-2025-8088 — WinRAR Path Traversal](https://nvd.nist.gov/vuln/detail/CVE-2025-8088)
