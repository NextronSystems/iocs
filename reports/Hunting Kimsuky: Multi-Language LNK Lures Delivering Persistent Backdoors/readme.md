# Hunting Kimsuky: Multi-Language LNK Lures Delivering Persistent Backdoors

In early September 2026, while reviewing THOR scanner matches on VirusTotal, I noticed a cluster of malicious `.lnk` files that stood out immediately. What looked like routine shortcut-based phishing turned out to be part of an **APT-C-55 (Kimsuky)** campaign using multilingual lure documents to deliver persistent backdoors through a layered chain of batch scripts, certutil abuse, and scheduled tasks.

Here's how the discovery unfolded and what we found inside.

## The Initial Detections

Between September 2 and October 1, THOR flagged nine LNK files across multiple VirusTotal submissions. Five of our YARA rules fired on the cluster, catching techniques that many AV engines were still missing at the time, with detection ratios hovering around **10-17 out of 60+**.

What immediately stood out was the **multilingual targeting**. The filenames were crafted in Korean, Japanese, Vietnamese, German, and English, all themed around contracts, insurance, invoices, and financial documents:

- `자산운용보고서_DS020_20867878.lnk` (Korean: Asset Management Report)
- `契約書_DS4092452_9745202742.lnk` (Japanese: Contract)
- `Hợp đồng mua bán_2745011321.lnk` (Vietnamese: Sales Contract)
- `Kaufvertrag_CS520423048_828429484.pdf.lnk` (German: Sales Contract)
- `Kaufvertrag_MS560482056_928030948.lnk` (German: Sales Contract)
- `Contract Agreement DS9092452_294635744.lnk` (English)
- `Insurance Documents FS805238_3084618338.lnk` (English)
- `Invoice_FS804378_3049618338_1736728927.pdf.lnk` (English)
- `Mexc_F20260730181137614nwZc2p0AR4Se02_212614603.png.lnk` (Crypto exchange lure)

Kimsuky has historically focused on South Korea, but this cluster shows a clear expansion to targets across multiple countries and language regions. The crypto exchange lure (`Mexc_...png.lnk`) is also notable, suggesting financial sector targeting beyond traditional insurance and government themes.

| SHA-256 | Filename | AV Ratio | First Seen |
|---------|----------|----------|------------|
| `0fc42583...` | 자산운용보고서_DS020_20867878.lnk | 29/63 | 2026-09-02 |
| `01f1a70b...` | Hợp đồng mua bán_2745011321.lnk | 27/60 | 2026-10-01 |
| `c470bef1...` | Kaufvertrag_CS520423048_828429484.pdf.lnk | 30/63 | 2026-10-01 |
| `8fb56f3d...` | Kaufvertrag_MS560482056_928030948.lnk | 29/63 | 2026-10-01 |
| `4555744f...` | 契約書_DS4092452_9745202742.lnk | 26/61 | 2026-10-01 |
| `85d3c150...` | Mexc_F20260730181137614nwZc2p0AR4Se02_212614603.png.lnk | 27/62 | 2026-10-01 |
| `27054417...` | Insurance Documents FS805238_3084618338.lnk | 28/63 | 2026-10-01 |
| `50de7dda...` | Invoice_FS804378_3049618338_1736728927.pdf.lnk | 30/63 | 2026-10-01 |
| `52fd47ca...` | Contract Agreement DS9092452_294635744.lnk | — | — |

All samples shared the same behavioral tags: `lnk`, `hiding-window`, `long-command-line-arguments`, `calls-wmi`, and `detect-debug-environment`, a consistent toolchain fingerprint across the entire cluster.

## Stage 1: The LNK Bootstrapper

The LNK files are the entry point. When a victim double-clicks what they think is a PDF or document, the shortcut executes a command that writes a base64-encoded malicious script into a temporary file. The trick is how it decodes it: the script copies `certutil.exe` from `System32` to `%TEMP%` under a randomized name (e.g., `ce<random>.exe`) and uses the copy to decode the payload into a batch script.

This is a well-known LOLBin technique, using a legitimate Microsoft tool to avoid detection. By copying and renaming certutil rather than calling it directly, they add another layer of evasion.

## Stage 2: Anti-Debug, Staging, and Persistence

The decoded second-stage BAT script starts with an anti-debugging check, exiting immediately if it detects a debugging process. If the coast is clear, it sets up shop:

**Staging directory**: `C:\Users\Public\Videos\Samples\` — a legitimate-looking path that blends in with default Windows folder structures.

**Configuration files**: Three files are written to the staging directory containing the attacker's GitHub repository path, the payload name (`init.dat`), and an authentication token. Using GitHub as infrastructure is a clever choice for blending with legitimate developer traffic.

**Decoy document delivery**: The script downloads a real-looking document from the repository and opens it for the victim, maintaining the illusion that they opened a legitimate file. If the download fails, it writes "Can not open document" as a fallback cover story. If the PDF already exists on disk, the host was previously infected — the script simply opens the document and exits to prevent reinfection.

**Persistence via scheduled task**: The script copies `certutil.exe` to `%TEMP%` as a renamed binary, then downloads `token.dat` from the repository, which is actually **nircmd** (a legitimate command-line utility). This gets saved as `Samples\ntoskrnl.exe` — disguised as a Windows kernel binary name. A scheduled task named `MicrosoftUpdate_<random>` is created to execute this binary every **9 minutes**, passing the path to the downloaded script with `exec hide` parameters.

**Fallback persistence**: If the nircmd download fails, the script generates a VBS file using `CreateObject("WScript.Shell")` with character-based obfuscation (using the character `5` to break up strings). This VBS runs the script in windowless mode and is also registered as a 9-minute scheduled task via `wscript.exe`.

**Cleanup**: At the end, the script deletes the certutil copy, the base64 temporary file, and the first-stage file, then deletes itself.

## Stage 3: C2 Communication and Data Theft

The third-stage script, triggered every 9 minutes by the scheduled task, reads its C2 configuration from the three files written in Stage 2. It pulls the machine's unique identifier (`MachineGuid` from `HKLM\SOFTWARE\Microsoft\Cryptography`) and uses it as a victim fingerprint.

The script continues the LOLBin abuse pattern, copying both `certutil.exe` and `curl.exe` to the staging directory under randomized names. It constructs GitHub download URLs and pulls down `init.dat` using the curl copy, falling back to certutil's URL cache if that fails. Downloaded payloads are verified (checking they start with the marker `jap`) and executed.

The `init.dat` payload is an information collection script that harvests:

- Hostname and computer name
- Account lists (`net user`)
- Process tables (`tasklist`)
- System information (`systeminfo`)
- Network configurations (`ipconfig`)
- User and program directory trees
- Recent documents

All collected data is written to a temporary file named after the victim's fingerprint and exfiltrated via HTTP POST to the attacker's server using the curl copy. After upload, all temporary files are deleted.

## Parallel Attack Path: PowerShell Variant

A second variant skips the batch script chain entirely. These LNK files invoke PowerShell directly with a double hex-encoded payload. Once decoded, the script:

1. Writes a persistent PowerShell function to `C:\Users\Public\<random>.ps1`
2. Creates a scheduled task for persistence
3. Downloads and opens a decoy PDF from the C2 server
4. Contacts `mf3goke.getenjoyment[.]net` as its C2, returning the user domain and username
5. Writes a secondary script to `%APPDATA%\Microsoft\gertg4wf.ps1`, executes it, then self-deletes after 5 seconds

## Supply Chain Poisoning: The pybroker Trojan

In the most sophisticated delivery method, the attackers cloned the legitimate open-source quantitative trading library **pybroker** on GitHub, embedding malicious code in the test infrastructure. When a developer clones the repository and runs `pytest`, the tampered `tests/conftest.py` automatically loads a malicious `.env` file, XOR-decrypts it with key `0x5A`, and executes the result.

The decrypted Python script downloads `key.enc` from a GitHub repository, decrypts it using a hardcoded **AES-GCM** key, saves the result as `C:\Users\Public\1.bat`, and runs it in windowless mode. The supply chain attack only triggers on Windows and disguises its return value as a random number seed.

The C2 URLs for this variant were constructed via string concatenation to resemble Python community sites:

| Indicator | Purpose |
|-----------|---------|
| `http://pythons.mywebcommunity[.]org` | Sign-in and return link |
| `https://pythoncomunity.wasmer[.]app/wp-content/uploads/` | Data exfiltration endpoint |

## The Rules That Caught It

Five YARA rules from our THOR and Valhalla rule sets fired on this cluster:

- [**SUSP_Recon_Suspicious_Dirs_Sep21_1**](https://valhalla.nextron-systems.com/info/rule/SUSP_Recon_Suspicious_Dirs_Sep21_1): Detects output redirection to suspicious folders like `C:\Users\Public` *(Florian Roth)*
- [**SUSP_LNK_ScriptContent_Apr21_1**](https://valhalla.nextron-systems.com/info/rule/SUSP_LNK_ScriptContent_Apr21_1): Catches LNK files with suspicious command lines *(Florian Roth)*
- [**SUSP_Base64_Obfuscated_Batch_Script_Apr25**](https://valhalla.nextron-systems.com/info/rule/SUSP_Base64_Obfuscated_Batch_Script_Apr25): Detects base64-encoded batch scripts used to hide malicious activity *(Pezier Pierre-Henri)*
- [**SUSP_SCRIPT_Lazarus_Cmdline_May21_1**](https://valhalla.nextron-systems.com/info/rule/SUSP_SCRIPT_Lazarus_Cmdline_May21_1): Flags commands that copy certutil from System32 — a technique shared with Lazarus group *(Florian Roth)*
- [**SUSP_Encoded_User_Public_Nov21**](https://valhalla.nextron-systems.com/info/rule/SUSP_Encoded_User_Public_Nov21): Detects encoded references to `C:\Users\Public` *(Florian Roth)*

It's worth noting the `SUSP_SCRIPT_Lazarus_Cmdline_May21_1` hit. While this rule was originally written to detect Lazarus (APT38) tradecraft, the certutil copy technique is now shared across multiple North Korean threat groups — both Kimsuky and Lazarus operate under the same state apparatus, and TTP overlap between them has been growing.

The layered detection is the key here. These are all `SUSP`-level (suspicious) rules rather than specific malware signatures, but together they paint a clear picture: an LNK file with embedded script content, base64-obfuscated batch code, certutil abuse, and `C:\Users\Public` as a staging directory. Each rule catches one piece of the kill chain. Stacked together, they're a high-confidence detection.

## IOCs

### File Hashes (SHA-256)

**Malicious LNK Files**
```
0fc425836eb854914525302b59cb8300b709c3e51ad776455a7eb5e29356d4f3
01f1a70bfc0016d3fceefb3b2133977a6a9649ad1c54280fcbbe1a8f9aad2149
c470bef115787abcc9a1d1df9213a072ab2b6daea5eaaa18a4378bca4d37f7df
8fb56f3d63e5dbc55695fe6e043707a933116ace43db4d3d67f42341a6540eef
4555744f4a328cddca885938f8fee83133be93c59be33a3e0b2906b536ee667c
85d3c1500e80b4782f3c1488adacfd14668ad99f3b4f01da3b0c4f31480745b4
2705441758889528e6cf333182799b2e51b458546e7706858e8789eaedb52562
50de7ddaf89d5aec643a449f7bb20e3b3ab5321bba1444a5c746ca4187170777
52fd47ca5f9a4bd2f5a87b4e9de502a93b1eaecdb3e4bf4a3fede0c34e01ab26
```

### Staging Paths

| Path | Purpose |
|------|---------|
| `C:\Users\Public\Videos\Samples\` | Primary staging directory |
| `C:\Users\Public\Videos\Samples\ntoskrnl.exe` | Renamed nircmd utility for scheduled task execution |
| `C:\Users\Public\Videos\Samples\mark.ini` | Infection marker (contains `jap`) |
| `C:\Users\Public\Videos\Samples\ini<random>.bat` | Decoded third-stage batch script |
| `%TEMP%\ce<random>.exe` | Renamed copy of certutil.exe |
| `%TEMP%\con<random>.exe` | Second renamed copy of certutil.exe |
| `Samples\task<random>.exe` | Renamed copy of curl.exe |
| `C:\Users\Public\<random>.ps1` | PowerShell variant persistence script |
| `%APPDATA%\Microsoft\gertg4wf.ps1` | PowerShell variant secondary script |
| `C:\Users\Public\1.bat` | Supply chain variant payload |

### Scheduled Tasks

| Task Name | Interval | Purpose |
|-----------|----------|---------|
| `MicrosoftUpdate_<random>` | Every 9 minutes | Persistent execution of Stage 3 |

### Network

| Indicator | Context |
|-----------|---------|
| `mf3goke.getenjoyment[.]net` | C2 server (PowerShell variant) |
| `http://pythons.mywebcommunity[.]org` | C2 sign-in endpoint (supply chain variant) |
| `https://pythoncomunity.wasmer[.]app/wp-content/uploads/` | Data exfiltration endpoint (supply chain variant) |
| GitHub repositories (attacker-controlled) | Payload hosting and C2 configuration |

