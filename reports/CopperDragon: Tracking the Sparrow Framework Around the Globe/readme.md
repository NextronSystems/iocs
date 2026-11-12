# CopperDragon: Tracking the Sparrow Framework Around the Globe

In November 2026, [Check Point Research published a report](https://research.checkpoint.com/2026/not-all-that-glitters-is-gold-tracking-copperdragons-sparrow-framework-around-the-globe/) on **CopperDragon**, a China-nexus "digital quartermaster" that builds and supplies the **Sparrow Framework** — a cross-platform toolkit descended from SparrowDoor — to several activity clusters that overlap with FamousSparrow, Earth Estries, Tropic Trooper and UAT-9244.

Check Point tracks three clusters using the framework:

- **SilentDelivery** — watering-hole sites serve jsjiami-obfuscated JavaScript that redirects visitors to a fake Chrome certificate-error page offering `CertFixer.msi`, which installs the **SquadC** loader through DLL sideloading (`MSVCR110.dll`, `dtfbase.dll`, `WTSAPI32.dll`). A spearphishing variant uses LNK files that abuse `ftp.exe -s:` to run a script.
- **OceanGate** — Windows and Linux intrusions using **SparrowShell**, **AnnobinDoor**, a SparrowDoor variant, trojanized `ssh`/`sshd` that harvest credentials, **CopperLogger**, **CopperLsa**, **CopperAdu**, **CopperList** and FRP for tunnelling.
- **DarkWire** — **CopperLoader** sideloads payloads by impersonating `libeay32.dll`, `libvlccore.dll`, `winfsp.dll`, `ncpmif32.dll` and others, to deliver **CopperDoor** (TLS backdoor), **CopperDNS** (DNS-tunnelling backdoor), **CopperProxy** (SOCKS5), **CopperLsass** (LSASS credential theft), **CopperSplit** and a renamed SoftEther VPN Bridge.

## Nextron Rule Coverage

We scanned 19 samples from the report. Every malicious sample triggered at least one rule. Two rules were written for this toolset in September 2026, about six weeks before the report was published. The remaining hits come from generic rules, some written years earlier.

| YARA Rule | Stage |
|---|---|
| [MAL_Backdoor_Loader_Sep26](https://valhalla.nextron-systems.com/info/rule/MAL_Backdoor_Loader_Sep26) | CopperLoader (`libeay32.dll`, `ncpmif32.dll`, `libjpeg-62.dll`, `winfsp.dll`) |
| [MAL_APT_SparroWock_Backdoor_Sep26](https://valhalla.nextron-systems.com/info/rule/MAL_APT_SparroWock_Backdoor_Sep26) | CopperDoor, CopperDNS |
| [MAL_Generic_Loader_Jul26](https://valhalla.nextron-systems.com/info/rule/MAL_Generic_Loader_Jul26) | SquadC loader (`dtfbase.dll`) |
| [MAL_Tropic_TrooperLoader_Sep24](https://valhalla.nextron-systems.com/info/rule/MAL_Tropic_TrooperLoader_Sep24) | SquadC loader (`WTSAPI32.dll`) |
| [SUSP_PEB_Walking_Jun25](https://valhalla.nextron-systems.com/info/rule/SUSP_PEB_Walking_Jun25) | CopperLoader (`libeay32.dll`, `libvlccore.dll`) |
| [SUSP_Sideloading_Cloaked_DLL_Aug22](https://valhalla.nextron-systems.com/info/rule/SUSP_Sideloading_Cloaked_DLL_Aug22) | SquadC loader (`MSVCR110.dll` in CAB) |
| [SUSP_LNK_FTP_Sep24](https://valhalla.nextron-systems.com/info/rule/SUSP_LNK_FTP_Sep24) | SilentDelivery spearphishing LNK |
| [SUSP_HKTL_Code_Indicator_Jul24](https://valhalla.nextron-systems.com/info/rule/SUSP_HKTL_Code_Indicator_Jul24) | CopperProxy |
| [Generic_Strings_Hacktools](https://valhalla.nextron-systems.com/info/rule/Generic_Strings_Hacktools) | CopperLsass RPC injector |
| [HKTL_PUA_FRP_FastReverseProxy_Oct21_1](https://valhalla.nextron-systems.com/info/rule/HKTL_PUA_FRP_FastReverseProxy_Oct21_1) | OceanGate tunnelling (`frpc`) |
| [SUSP_PUA_SoftEther_VPNGate_Sftware_Dec21_1](https://valhalla.nextron-systems.com/info/rule/SUSP_PUA_SoftEther_VPNGate_Sftware_Dec21_1) | DarkWire tunnelling (`vmtoolsd.exe`) |
| [EXT_MAL_LNX_SSHDOOR_Triton](https://valhalla.nextron-systems.com/info/rule/EXT_MAL_LNX_SSHDOOR_Triton) | OceanGate trojanized `ssh` |

### Timeline

Every rule that fired was in place before Check Point published on **2026-11-10**. The month in each rule name shows when it was written. The date THOR reports is the date of the rule's latest revision.

- **Dec 2018 / Oct 2021 / Dec 2021** — `EXT_MAL_LNX_SSHDOOR_Triton`, `HKTL_PUA_FRP_FastReverseProxy_Oct21_1` and `SUSP_PUA_SoftEther_VPNGate_Sftware_Dec21_1` cover the OceanGate and DarkWire tunnelling and credential-harvesting tools
- **Aug 2022** — `SUSP_Sideloading_Cloaked_DLL_Aug22` covers the `MSVCR110.dll` sideloading DLL
- **Jul–Sep 2024** — `SUSP_HKTL_Code_Indicator_Jul24`, `SUSP_LNK_FTP_Sep24` and `MAL_Tropic_TrooperLoader_Sep24` cover CopperProxy, the `ftp.exe` LNK lure and the `WTSAPI32.dll` SquadC loader
- **Jun 2025** — `SUSP_PEB_Walking_Jun25` covers the CopperLoader variants that the dedicated loader rule misses
- **2026-07-14** — `MAL_Generic_Loader_Jul26` covers the `dtfbase.dll` SquadC loader
- **2026-09-25** — `MAL_Backdoor_Loader_Sep26` and `MAL_APT_SparroWock_Backdoor_Sep26` are written specifically for CopperLoader, CopperDoor and CopperDNS

### Scanned Samples

| SHA-256 | Malware (Check Point) | Cluster | THOR Rule | Score |
|---|---|---|---|---|
| `054c0ffb08eb7830de1ff2356af4d2ed696f01111a8c2e78e3a4ddc940287e48` | SquadC loader (`dtfbase.dll`) | SilentDelivery | MAL_Generic_Loader_Jul26 | 75 |
| `b60404c1299e69df029d9817dcf69f9fe325ecc990e16bc7758f56ce5714184b` | SquadC loader (`WTSAPI32.dll`) | SilentDelivery | MAL_Tropic_TrooperLoader_Sep24 | 80 |
| `3e4eef1a641d6060f6144ceba6757df6085d475eedb8b9e61b5feb84e9fb989e` | FRP client (`frpc`) | OceanGate | HKTL_PUA_FRP_FastReverseProxy_Oct21_1 | 75 |
| `ea25b021f90dbd1c53cd3490274c5c92856d4f815d85f3ec68600facab2c952f` | Trojanized `ssh` | OceanGate | EXT_MAL_LNX_SSHDOOR_Triton | 75 |
| `125525a38abc45e855f848d499582a8100f1428938d4bd3d3eba957072e64e7a` | CopperLoader (`libeay32.dll`) | DarkWire | MAL_Backdoor_Loader_Sep26 | 80 |
| `12b6d5ca7aca7134032721b6feb8e4d5ad75c886fbf8a5889d3d36971a083681` | CopperLoader (`libeay32.dll`) | DarkWire | SUSP_PEB_Walking_Jun25 | 70 |
| `4cafda69af3179ceb4a1f5ed864c501279796254709c86ca236be1cf74a8643f` | CopperLoader (`ncpmif32.dll`) | DarkWire | MAL_Backdoor_Loader_Sep26 | 80 |
| `a47279e4ee703092263e7030c43c61533146c00689e7cb8f2080f18e57d5cf7f` | CopperLoader (`libjpeg-62.dll`) | DarkWire | MAL_Backdoor_Loader_Sep26 | 80 |
| `d4e4a3f55b875673cfdb6d0687cc3f8890585210806b03082d11fb4fa40b57de` | CopperLoader (`libvlccore.dll`, VLC version info) | DarkWire | SUSP_PEB_Walking_Jun25 | 70 |
| `f01a73f651f8113bf9672dbe4c50c63ed365a41e4187aaf0a5ab34cd21154046` | CopperLoader (`winfsp.dll`, WinFsp version info) | DarkWire | MAL_Backdoor_Loader_Sep26 | 80 |
| `d08e09a17df22fb39838dcc9e99756830ef5175bc9e03d615adf979dc85ed052` | CopperDoor | DarkWire | MAL_APT_SparroWock_Backdoor_Sep26 | 80 |
| `417664cc34360d8519adc7a019408cf8f37f59c95a44e50092d73e38b7889a21` | CopperDNS | DarkWire | MAL_APT_SparroWock_Backdoor_Sep26 | 80 |
| `3a1b7ec461d656524e612b228ce969bfa612c799fb7117bb066352ff776d88da` | CopperProxy | DarkWire | SUSP_HKTL_Code_Indicator_Jul24 | 60 |
| `fd0861a8269f2bb2fe0adfb4b4610d9675e68474503598f83e87c29b88906f99` | CopperLsass RPC injector | DarkWire | Generic_Strings_Hacktools | 60 |
| `4f9d9a6cba88832fcb7cfb845472b63ff15cb9b417f4f02cb8086552c19ceffc` | SoftEther VPN Bridge (`vmtoolsd.exe`) | DarkWire | SUSP_PUA_SoftEther_VPNGate_Sftware_Dec21_1 | 60 |
| `1a442a8e12c1571a0663e64e0ac9c930035bb267259b684cd9607f76be6d017b` | CAB containing SquadC loader *(not in report)* | SilentDelivery (assessed) | via embedded `MSVCR110.dll` | 70 |
| `c69534bb3e6d4e1c9b21f9e4745f6fb002cbcd3ab83f9ad208eb7bb135401062` | SquadC loader (`MSVCR110.dll`) *(not in report)* | SilentDelivery (assessed) | SUSP_Sideloading_Cloaked_DLL_Aug22 | 70 |
| `4c7ae604ad1af90ea155865cb28fd7ccd6371f5ac172de6014b328514d4618e7` | LNK running `ftp.exe -s:_rels\info.dll` *(not in report)* | SilentDelivery (assessed) | SUSP_LNK_FTP_Sep24 | 70 |

The last three samples are not listed by Check Point. We attribute them to SilentDelivery based on technique overlap: the same `MSVCR110.dll` sideloading name, and the `ftp.exe -s:` LNK execution chain the report describes.

## Indicators of Compromise

### Files

#### SilentDelivery

| SHA-256 | Filename | Description |
|---|---|---|
| `715c206629f59ff5b0134a33362162ce7a40a9b25aa17f0543dc9648d51a67cf` | CertFixer.msi | SquadC installer (fake certificate fix) |
| `b379d07ba81d4190490d9893b2d6d830ff594e042dce26053ef07794d0403787` | CertFixer.msi | SquadC installer |
| `e5f7bbfc187264336dea5dfebfb5a7dd1e7fcdcc9692db55fbe6eb4d28f027bc` | CertFixer.msi | SquadC installer |
| `e9f2f42ea3611096879f4152a7d78bb3a78a4dbead1c3b7e366dce485207551f` | CertFixer.msi | SquadC installer |
| `f44159bec1d4d3f340652cd3c6e250dcf2bdb266e5400d3e267f0466d290dda0` | CertFixer.msi | SquadC installer |
| `f51dc5e1848daee4e607d46faa25033e1151060cd3482ad4439754440d6c4c01` | CertFixer.msi | SquadC installer |
| `8bbc395a7a0faff074c6e31c7da37bf1540a4e7ec3d80870f8d6bd1f5d4cecbb` | MSVCR110.dll | SquadC loader |
| `f23e5391656b178bc0ab510b0fca6ffbd963cf94870c82a5920f0f338f561f18` | MSVCR110.dll | SquadC loader |
| `c69534bb3e6d4e1c9b21f9e4745f6fb002cbcd3ab83f9ad208eb7bb135401062` | MSVCR110.dll | SquadC loader (Nextron hunting) |
| `1a442a8e12c1571a0663e64e0ac9c930035bb267259b684cd9607f76be6d017b` | — | CAB archive delivering `MSVCR110.dll` (Nextron hunting) |
| `054c0ffb08eb7830de1ff2356af4d2ed696f01111a8c2e78e3a4ddc940287e48` | dtfbase.dll | SquadC loader |
| `b60404c1299e69df029d9817dcf69f9fe325ecc990e16bc7758f56ce5714184b` | WTSAPI32.dll | SquadC loader |
| `4c7ae604ad1af90ea155865cb28fd7ccd6371f5ac172de6014b328514d4618e7` | — | Spearphishing LNK abusing `ftp.exe` (Nextron hunting) |

#### OceanGate

| SHA-256 | Filename | Description |
|---|---|---|
| `1cd0c608418cca80149ef3077e54969f24cd7ef3f22707cb280fa4b378ffa76b` | filst2.exe | CopperList |
| `40880b6fce6f83df4e902cd29d7abb303ffa3f37c429c382f2aaeea34f7be074` | adu.exe | CopperAdu (creates local admin, opens SMB) |
| `9fa421adb5c5dac3b2fc1165b0dddd596e82cfd3b08347a91d63f9e88d8718d0` | g.exe | CopperLsa |
| `3637f4f804cffc3b25222d542e7cb544ee48074ed2e46607e31f9410c17bf223` | STI.DLL | CopperLogger loader |
| `1b365975f9ad8a4748b2bbfb36de3be171aeadeb59d497192a8b4d9560b37173` | — | CopperLogger (in-memory payload) |
| `d1da8e2389f48d1d1c0e127f3417e3d3e0dbf54691e22d6d0c863d28b9e7a812` | hha.dll | SparrowDoor loader |
| `dbdaa8a52246b1e3f9285820db2f976b8ab513926ed972c968fae1c8aeb77056` | — | SparrowDoor variant (in-memory payload) |
| `46407cc35c48d19c6b1990a03ebdd19321005ce08d5a98acd168fda55a92d946` | containerd-demo | AnnobinDoor (Linux) |
| `3e4eef1a641d6060f6144ceba6757df6085d475eedb8b9e61b5feb84e9fb989e` | frpc | FRP client used for tunnelling |
| `cc3544ac194a4ab5f3a60dbedd270192bc01afd2a365b3b136b35d40d8dd3ff0` | ssh | Trojanized OpenSSH client |
| `ea25b021f90dbd1c53cd3490274c5c92856d4f815d85f3ec68600facab2c952f` | ssh | Trojanized OpenSSH client |
| `fa28bc5dfc2c37c3104961f5ca80f590259a27743a8aa327c606fb51452b840f` | sshd | Trojanized OpenSSH server |
| `2ea96ea398e9254706ff2761b86302372c149ef090536ad76231e51d7c810a2a` | xfs_rudp | SparrowShell (Linux) |
| `50daadd49b8df4f0190d0badfde89f8e6a6e61af664ef1444984028a005f40d8` | aplk | SparrowShell (Linux) |
| `cbce7dc8649b37c5db411dfee3a74e8cace2b48fdc8350bfa5b4846c5d9ed2ae` | 2000 | SparrowShell plugin |
| `9d01724193d9570a6c75bbcbb171d29df290207007d004cf75d133dd9aa475f4` | 3000 | SparrowShell plugin |
| `129349a221e6efcc9a047efdfd81197f796fcf38877344f17f85651b21e33427` | 4000 | SparrowShell plugin |

#### DarkWire

| SHA-256 | Filename | Description |
|---|---|---|
| `4cafda69af3179ceb4a1f5ed864c501279796254709c86ca236be1cf74a8643f` | ncpmif32.dll | CopperLoader |
| `48dcc07d9f87129e937f5ca2ad5ba56975600efb8a7280a170b2aeeff503f595` | ncpmif32.dll | CopperLoader |
| `a47279e4ee703092263e7030c43c61533146c00689e7cb8f2080f18e57d5cf7f` | libjpeg-62.dll | CopperLoader |
| `d4e4a3f55b875673cfdb6d0687cc3f8890585210806b03082d11fb4fa40b57de` | libvlccore.dll | CopperLoader |
| `3317789219e9b3e48fbb8f7af23359a37539597fc4d84649086aec71a21553ee` | libvlc.dll | CopperLoader |
| `c049e5e03a04cf54f8aa089c65861342d3fb4aa8d6a2b1c9484637c46ddc3882` | winfsp.dll | CopperLoader |
| `f01a73f651f8113bf9672dbe4c50c63ed365a41e4187aaf0a5ab34cd21154046` | winfsp.dll | CopperLoader |
| `9332f9cd283d69e9a2a2bb71575054cc71c14b6496ac55f7ff43efdcb6d97a01` | winfsp-x64.dll | CopperLoader |
| `12b6d5ca7aca7134032721b6feb8e4d5ad75c886fbf8a5889d3d36971a083681` | libeay32.dll | CopperLoader |
| `125525a38abc45e855f848d499582a8100f1428938d4bd3d3eba957072e64e7a` | libeay32.dll | CopperLoader |
| `4b1fea3265492ad1d272428447fb5919bbe3184131b12a0ae84caf3bc442718e` | zCrashReport64.dll | CopperLoader |
| `4e50f53b5294a6dbd601fc20a607ae85725162b596119f4867311ef0b3f75a6a` | DukeQt.dll | Shellcode loader |
| `f42461c386834d61780da13760a130ed2ea620627b5eebf97b56237058ea380d` | zCrashReport64.dll | CopperSplit |
| `b7060cf7955a1f1caac2bc3d0918c9b1d9daa315c5d82b329acd3bbddb413948` | tempdir.dll | CopperSplit |
| `cb714decdcabe30008546e6fb71bb28e390c9bd186bf2549aaa8fe5b999200a5` | asinteg.dll | CopperSplit helper |
| `de6a3140797f7c00a48b2068127965c3994f92867466259e69c861880e6ec2d8` | — | CopperDoor (in-memory payload) |
| `d08e09a17df22fb39838dcc9e99756830ef5175bc9e03d615adf979dc85ed052` | — | CopperDoor (in-memory payload) |
| `417664cc34360d8519adc7a019408cf8f37f59c95a44e50092d73e38b7889a21` | — | CopperDNS (in-memory payload) |
| `3a1b7ec461d656524e612b228ce969bfa612c799fb7117bb066352ff776d88da` | — | CopperProxy SOCKS5 tool (in-memory payload) |
| `fd0861a8269f2bb2fe0adfb4b4610d9675e68474503598f83e87c29b88906f99` | — | CopperLsass RPC injector (in-memory payload) |
| `916a16a4a1eb7393b17574835312725e5cb146995a3cbcdf42fa8b9bebaa51b1` | slave.dll | CopperLsass MiniDump module |
| `675a44c679dea8d40b3885c37168929f976e3a0ecacc7e02c6b07936ac58a9fc` | dep.dll | CopperLsass helper |
| `ee8c148518c5a416fc7d9b33246e9c98d955f2379aa9c82225e045322c97a043` | sqlmap.exe | PyProxy (Python proxy, not sqlmap) |
| `4f9d9a6cba88832fcb7cfb845472b63ff15cb9b417f4f02cb8086552c19ceffc` | vmtoolsd.exe | SoftEther VPN Bridge (`vpnbridge_x64.exe`) renamed as a VMware Tools process |

> **Note:** `frpc` and the SoftEther `vmtoolsd.exe` are repurposed legitimate tools. Their hashes are reliable within this intrusion set. But if either hash matches an official release, the hit alone does not prove compromise. Look for the masquerading name or an unexpected location, such as `vmtoolsd.exe` outside `C:\Program Files\VMware\VMware Tools\`.

### Network

#### Domains

| Indicator | Cluster |
|---|---|
| `microsfot[.]vip` | SilentDelivery |
| `microscoft[.]vip` | SilentDelivery |
| `aistei[.]com` | SilentDelivery |
| `astorialaza[.]com` | SilentDelivery |
| `windowsdefender.it[.]com` | OceanGate |
| `windowsupdates[.]us` | OceanGate |
| `microupdate[.]me` | OceanGate |
| `windefender[.]net` | OceanGate |
| `seosnskorea[.]com` | DarkWire |
| `amelicen[.]com` | DarkWire |
| `jamvybez[.]com` | DarkWire |
| `artfingo[.]com` | DarkWire |
| `faceorkut[.]com` | DarkWire |
| `aauctioneer[.]com` | DarkWire |

#### IP Addresses

Most of these addresses are rented VPS (for example the `216.238.0.0/16` and `38.54.0.0/16` / `38.60.0.0/16` ranges), and the operators rotate them. Treat a match as a lead tied to the reporting period, not as a standalone verdict.

| Indicator | Cluster |
|---|---|
| `2.56.222[.]28` | OceanGate |
| `2.56.222[.]49` | OceanGate |
| `37.122.150[.]133` | OceanGate |
| `38.54.45[.]155` | DarkWire |
| `38.54.57[.]12` | DarkWire |
| `38.54.71[.]56` | OceanGate |
| `38.54.71[.]107` | OceanGate |
| `38.54.71[.]160` | OceanGate |
| `38.60.195[.]184` | OceanGate |
| `38.60.206[.]85` | DarkWire |
| `38.60.209[.]65` | DarkWire |
| `38.60.209[.]227` | OceanGate |
| `38.60.214[.]237` | DarkWire |
| `38.60.241[.]65` | DarkWire |
| `38.60.241[.]193` | DarkWire |
| `38.60.242[.]182` | DarkWire |
| `45.39.103[.]5` | OceanGate |
| `45.76.215[.]17` | DarkWire |
| `45.80.208[.]66` | OceanGate |
| `45.80.208[.]195` | OceanGate |
| `45.80.208[.]232` | OceanGate |
| `45.86.230[.]60` | OceanGate |
| `45.90.58[.]202` | OceanGate |
| `45.197.12[.]11` | SilentDelivery |
| `47.81.8[.]145` | OceanGate |
| `64.176.6[.]27` | DarkWire |
| `64.176.10[.]7` | DarkWire |
| `64.190.113[.]170` | OceanGate |
| `77.111.101[.]11` | DarkWire |
| `77.111.101[.]153` | DarkWire |
| `77.111.101[.]227` | DarkWire |
| `87.236.37[.]185` | OceanGate |
| `89.44.193[.]140` | OceanGate |
| `89.223.91[.]91` | OceanGate |
| `91.210.164[.]5` | SilentDelivery, OceanGate |
| `91.227.77[.]172` | OceanGate |
| `92.118.127[.]23` | OceanGate |
| `103.9.77[.]116` | OceanGate |
| `103.141.235[.]123` | SilentDelivery |
| `103.215.216[.]27` | OceanGate |
| `103.215.216[.]75` | OceanGate |
| `103.215.216[.]116` | OceanGate |
| `103.215.216[.]117` | OceanGate |
| `103.215.216[.]123` | OceanGate |
| `103.215.216[.]125` | OceanGate |
| `103.215.216[.]162` | OceanGate |
| `103.215.216[.]186` | OceanGate |
| `103.215.216[.]197` | OceanGate |
| `108.61.161[.]250` | DarkWire |
| `109.205.195[.]131` | SilentDelivery, OceanGate |
| `130.94.91[.]53` | OceanGate |
| `134.255.211[.]224` | OceanGate |
| `135.136.135[.]54` | SilentDelivery |
| `149.104.12[.]128` | DarkWire |
| `149.104.87[.]222` | DarkWire |
| `149.104.87[.]228` | DarkWire |
| `149.104.90[.]200` | OceanGate |
| `151.242.188[.]220` | OceanGate |
| `153.127.55[.]77` | OceanGate |
| `154.205.154[.]70` | OceanGate |
| `154.205.154[.]82` | OceanGate |
| `154.223.21[.]194` | OceanGate |
| `156.244.2[.]26` | DarkWire |
| `158.255.213[.]189` | SilentDelivery |
| `160.16.83[.]208` | OceanGate |
| `165.154.226[.]247` | OceanGate |
| `165.154.227[.]16` | SilentDelivery, OceanGate |
| `165.154.243[.]24` | OceanGate |
| `167.179.109[.]141` | DarkWire |
| `180.149.44[.]43` | OceanGate |
| `180.149.44[.]115` | OceanGate |
| `181.41.201[.]244` | DarkWire |
| `185.93.173[.]30` | DarkWire |
| `188.214.157[.]51` | DarkWire |
| `194.213.18[.]178` | OceanGate |
| `207.189.10[.]188` | OceanGate |
| `216.185.57[.]152` | OceanGate |
| `216.238.71[.]215` | DarkWire |
| `216.238.73[.]14` | DarkWire |
| `216.238.85[.]243` | DarkWire |
| `216.238.90[.]160` | DarkWire |
| `216.238.106[.]177` | DarkWire |
| `216.238.107[.]140` | DarkWire |
| `216.238.110[.]120` | DarkWire |
| `216.238.111[.]30` | DarkWire |
| `216.238.113[.]122` | DarkWire |
| `216.238.115[.]152` | DarkWire |
| `216.238.118[.]179` | OceanGate |
| `216.238.119[.]130` | DarkWire |
| `216.238.120[.]8` | DarkWire |
| `216.238.121[.]254` | DarkWire |
| `216.238.123[.]242` | OceanGate |
| `217.69.13[.]77` | OceanGate |

#### C2 Patterns and Certificates

| Indicator | Description |
|---|---|
| `/image-check?t=` | SquadC C2 URI (followed by a timestamp) |
| `/report-url` | SquadC C2 URI |
| `/register-ip` | SquadC C2 URI |
| `760be920fad07881b8ce9d94e074a35b4f806717` | SHA-1 of the TLS certificate shared by SilentDelivery and OceanGate servers (fake "VeriSign Class 3 Code Signing 2010 CA" subject, issuer CN `McAfee, Inc.`) |
| `ee4a8b81fe3864582efc27a77f806990e2602dcc36447ddda4b3a230a473d575` | SHA-256 of the CopperDNS node TLS certificate (subject and issuer CN `8.8.8.8`) |
| TCP `6532` | Port commonly exposed on CopperDNS nodes |

### Host

| Indicator | Description |
|---|---|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateAssist` | SquadC persistence. The Run value name imitates Windows Update Assistant. |
| `\\.\pipe\ccpipe` | Named pipe used by CopperDoor and CopperDNS |
| `/var/cache/opt/.ots` | Credential log written by the trojanized `ssh` client |
| Firewall rule `RasiUwpApp` | Deleted and recreated by CopperAdu to allow SMB (TCP/445) |
| Firewall rule `ss1` | Created by CopperProxy for its SOCKS5 listener |
| Local account `admin$` | Created by CopperAdu (hard-coded password `Admin@123456`) |
| TCP `49628` (local listener) | SparrowDoor variant passive-mode listener |

#### DLL Sideloading Pairs (DarkWire)

The DLL names are legitimate. The indicator is a copy of the signed host binary next to the DLL in a staging directory where neither belongs. Check Point names `C:\ProgramData\USOShared`, `C:\ProgramData\Waves`, `C:\ProgramData\vmware\logs`, `C:\ProgramData\Oracle\Java`, `C:\Program Files\7-Zip\Lang` and `C:\Windows\debug`.

| Hijacked DLL | Legitimate Host Binary |
|---|---|
| `ncpmif32.dll` | `ncptrcw.exe` |
| `winfsp.dll` | `fsptool.exe` |
| `libvlccore.dll` | `vlc.exe` |
| `DukeQt.dll` | `gethwid.exe` |
| `zCrashReport64.dll` | `zCrashReport64.exe` |

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Drive-by Compromise | [T1189](https://attack.mitre.org/techniques/T1189/) | Watering-hole sites redirect visitors to a fake Chrome certificate-error page |
| Phishing: Spearphishing Attachment | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | LNK and CAB lures delivering SquadC |
| User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Victim runs `CertFixer.msi` or opens the LNK |
| Indirect Command Execution | [T1202](https://attack.mitre.org/techniques/T1202/) | LNK launches `ftp.exe -s:` to run a script |
| Hijack Execution Flow: DLL Side-Loading | [T1574.002](https://attack.mitre.org/techniques/T1574/002/) | SquadC and CopperLoader sideloaded by signed binaries |
| Masquerading: Match Legitimate Name or Location | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | `libeay32.dll`, `winfsp.dll`, `libvlccore.dll`, `vmtoolsd.exe`, `sqlmap.exe` |
| Obfuscated Files or Information: Dynamic API Resolution | [T1027.007](https://attack.mitre.org/techniques/T1027/007/) | PEB walking in CopperLoader |
| Virtualization/Sandbox Evasion: System Checks | [T1497.001](https://attack.mitre.org/techniques/T1497/001/) | SquadC checks for running browsers before executing |
| Boot or Logon Autostart Execution: Registry Run Keys | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | `WindowsUpdateAssist` Run value |
| Compromise Host Software Binary | [T1554](https://attack.mitre.org/techniques/T1554/) | Trojanized `ssh` and `sshd` |
| OS Credential Dumping: LSASS Memory | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | CopperLsass, CopperLsa |
| Create Account: Local Account | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | CopperAdu creates `admin$` |
| Impair Defenses: Disable or Modify System Firewall | [T1562.004](https://attack.mitre.org/techniques/T1562/004/) | `RasiUwpApp` and `ss1` firewall rules |
| Remote Services: SMB/Windows Admin Shares | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | CopperAdu lateral movement over SMB |
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | SquadC HTTP C2 |
| Application Layer Protocol: DNS | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | CopperDNS tunnelling over MX queries |
| Encrypted Channel | [T1573](https://attack.mitre.org/techniques/T1573/) | CopperDoor TLS C2 on port 443 |
| Proxy | [T1090](https://attack.mitre.org/techniques/T1090/) | CopperProxy SOCKS5, PyProxy |
| Protocol Tunneling | [T1572](https://attack.mitre.org/techniques/T1572/) | FRP and SoftEther VPN Bridge |

## References

- [Check Point Research: Not All That Glitters is Gold — Tracking CopperDragon's Sparrow Framework Around the Globe](https://research.checkpoint.com/2026/not-all-that-glitters-is-gold-tracking-copperdragons-sparrow-framework-around-the-globe/) (November 2026)
- [Aziz Farghly (Nextron Systems) on X: CopperDragon / Sparrow Framework detections](https://x.com/FarghlyMal/status/2103808005296857408)
