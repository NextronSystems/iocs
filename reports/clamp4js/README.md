# clamp4js: npm Dropper in the clampony / safeclamp3 Campaign

## 1. Executive Summary

`clamp4js` (npm) belongs to the same campaign as `clampony` and `safeclamp3`. Its Telegram stealer and RAT chain is live. Static analysis of `clamp4js` 1.0.13 only, nothing was executed.

- **Decoy URLs:** the `officeapps.live.com` and `dl.google.com` URLs in `install.js` are decoys. `normalize()` (mod-257 rotating table, `install.js:29-48`) rewrites them to `hxxps://pastebin[.]com/raw/z6K1Rg8J` and `hxxps://calcal[.]ru/p/t5edjvR/raw`.
- **Stealer:** both hosts serve the same 49,280 B Windows stealer, byte-identical to SafeDep's sample (SHA-256 `ca2b7eced5937817b2aca2d50542d2e171bc95593be72a94c158616ed17a5334`). Same Telegram `chat_id` `7638757988`, same stage 3 host.
- **Behaviour of 1.0.13:** it saves the stealer to `%TEMP%\<UUID>` and beacons `urlto[.]me/2rrih`, but never runs it. `clampony` runs `setup.js` at preinstall.
- **Stage 3 rebuilt:** our fetch (26 Nov) is 381,440 B with PE timestamp 25 Nov 02:29 UTC. SafeDep's is 352,256 B, 24 Nov 00:03 UTC. Same family: UA `enterotoxin/0.1`, `MicrosoftStoreUpdater`, `events.ksp`, `obj-*.spy`, `/enterotoxin/<id>/control`.

**Credit**
- Vigilance caught the `clamp4js` dropper about one minute after it hit npm (1.0.9, 25 Nov): https://vigihq.com/attacks/clamp4js-npm-installer-dropper
- SafeDep dissected the siblings `clampony` / `safeclamp3` and the payload (24 Nov): https://safedep.io/blog/clampony-npm-preinstall-telegram-stealer

## 2. Infection Chain

`npm install` → decoy URLs decoded by `normalize()` → pastebin / calcal → Windows stealer (SSH keys, AWS/GCP/Azure/kube/docker/terraform, npm/pypi/git credentials, FileZilla/WinSCP/MobaXterm, shell histories, Telegram `tdata`) → zip → Telegram Bot API via 9 proxies. A second path delivers the `enterotoxin.exe` RAT from `195[.]123[.]6[.]29`.

## 3. Indicators of Compromise

### Packages
| Package | Versions | Notes |
|---|---|---|
| `clamp4js` | 1.0.5 - 1.0.13 | 1.0.2 and 0.0.0-stage are empty |
| `clampony` | 1.0.1, 1.0.6, 1.0.7, 1.0.9, 1.0.10, 1.0.11 | npm user `tinafo6772` |
| `safeclamp3` | 1.0.7, 1.0.11 | npm user `felisox354` |

### Payload and beacon
| Type | Value |
|---|---|
| Payload URL | `hxxps://pastebin[.]com/raw/z6K1Rg8J` |
| Payload URL | `hxxps://calcal[.]ru/p/t5edjvR/raw` |
| RAT URL | `hxxps://195[.]123[.]6[.]29:443/enterotoxin.exe` |
| Beacon | `hxxps://urlto[.]me/2rrih` |

### C2 / exfiltration
| Type | Value |
|---|---|
| C2 | `195[.]123[.]6[.]29:443` and TCP `13599` (per SafeDep) |
| Exfil | `api[.]telegram[.]org` Bot API, bot ID `9249894009`, `chat_id` `7638757988` |
| Banner | `EnterotoxinControl/1 Python/3.13.5` |

### Exfil proxies (auth embedded)
| Proxy |
|---|
| `199[.]247[.]15[.]159:11409` |
| `160[.]116[.]1[.]30:8000` |
| `45[.]153[.]20[.]239:11665` |
| `70[.]38[.]2[.]13:10300` |
| `45[.]145[.]57[.]208:11928` |
| `85[.]195[.]81[.]159:11838` |
| `108[.]61[.]251[.]204:13571` |
| `45[.]153[.]20[.]234:13906` |
| `45[.]91[.]209[.]153:11015` |

### Host artefacts
| Type | Value |
|---|---|
| File | `%TEMP%\<UUID>` (no extension) |
| File | `%TEMP%\<UUID>.exe` (stage 3, deleted after 6 s) |
| Staging | `%TEMP%\files-staging-\` and `sysvolume.zip` |
| Telegram folder | `tdata` folder `D877F783D5D3EF8C` |
| File | `%LOCALAPPDATA%\Programs\Microsoft Store\MicrosoftStoreUpdaterV<n>.exe` (per SafeDep) |
| File | `%LOCALAPPDATA%\Microsoft\Store\UpdateCache\obj-*.spy`, `events.ksp` (per SafeDep) |

### Files (SHA-256 / SHA-1)
| Role | Hash |
|---|---|
| `install.js` | `dd7d2f8d20473648b6b0bc0d1ba2cda9ae489ca6fb75df11a319e321bc969dac` |
| `package.json` | `22cd34fbee3068f3ba6b990061a0041eb1894e203bd16f1ac7f113b58d7e2eac` |
| `index.js` | `70b6fb0d5bf7e3f8ba121fd582208956bbd7b62aa715faba538385b32e432ac4` |
| Stealer (49,280 B) | `ca2b7eced5937817b2aca2d50542d2e171bc95593be72a94c158616ed17a5334` |
| Stage 3 (381,440 B) SHA-256 | `161b41555cd08ecabb3f1d5e69627a557b84c7c30c187cb2371b0e78421a1efb` |
| Stage 3 (352,256 B, SafeDep) SHA-256 | `48cf14560a8c2c5eaa984078cb345a81bc6d49d6695a06851499a3a31260aa91` |
| Stage 3 (381,440 B) SHA-1 | `f4c6e2e32b18f3fc8bc2d508c76d27b3ba1db74a` |
| `clamp4js` 1.0.13 tgz SHA-1 | `e5ebc6f308e88b98687c521996f897d79138b2ea` |

### Decoys (do not block)
`officeapps.live.com` and `dl.google.com` appear in `install.js` but are never requested as written.
