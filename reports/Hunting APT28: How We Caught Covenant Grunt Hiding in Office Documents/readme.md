# Hunting APT28: How We Caught Covenant Grunt Hiding in Office Documents

Back in July 2026, while reviewing THOR scanner matches on VirusTotal, I came across a cluster of malicious Office documents that immediately caught my attention. What started as a handful of suspicious `.xls` and `.docm` files turned out to be part of an APT28 (Fancy Bear) campaign delivering the **Covenant Grunt** backdoor, the same tooling Zscaler documented in their [Operation NeuSploit](https://www.zscaler.com/blogs/security-research/apt28-leverages-cve-2026-21509-operation-neusploit) report tied to CVE-2026-21509.

Here's how the discovery unfolded and what we found inside.

## The Initial Detections

Between July 8 and July 14, THOR flagged seven Office documents. The first thing that stood out was how poorly traditional AV engines were doing. Some of these files had detection ratios as low as **5 out of 62**. Our YARA rules were among the few things catching them.

The samples used business-themed filenames designed to trick victims into opening them:

- `accounts.xls`
- `trix.xls`
- `Прайс.xls` (Russian for "Price List")

The Russian-language lure was a strong hint about the intended targets. Combined with the filenames like `accounts.xls`, this looked like a classic spearphishing setup aimed at Russian-speaking organizations, something very much in APT28's wheelhouse.

| SHA-256 | Filename | Type | AV Ratio | First Seen |
|---------|----------|------|----------|------------|
| `2d8f5187a620...` | ~document.docm.tmp | DOCM | 33/67 | 2026-07-14 |
| `74ffcff4d461...` | *(unnamed)* | XLS | 5/62 | 2026-07-14 |
| `a14dc55a66c5...` | *(unnamed)* | XLS | 15/62 | 2026-07-14 |
| `d1ec65537daf...` | accounts.xls | XLS | 5/62 | 2026-07-14 |
| `debd7a84b7b9...` | trix.xls | XLS | 33/63 | 2026-07-08 |
| `e20413254a14...` | ~trix.xls.tmp | XLS | 22/61 | 2026-07-14 |
| `fa0e68457b06...` | Прайс.xls | XLS | — | — |

## Digging Into the Macros

I pulled the VBA code from the DOCM sample (`2d8f5187...`) and started picking it apart. The macros in **Module8** weren't sophisticated in terms of technique, but they used enough string obfuscation to slip past a lot of static scanners.

The first thing the macro does on document open is figure out where it lives on disk. It resolves the user's profile path by assembling the string `"userprofile"` from fragments (`"use"` + `"rpro"` + `"file"`) and passes it to `Environ()`. Then it builds a path to the victim's OneDrive folder using the same trick (`"On"` + `"eDrive"`), and copies the document there:

```vb
prtuprf = "rpro"
uprf = VBA.Environ("use" & prtuprf & "file")   ' → %USERPROFILE%
origPath = uprf & pthPrt & "/On" & drvst        ' → OneDrive path
fso.CopyFile origPath, dstCpFl
```

It's simple concatenation, but it works. Enough AV engines rely on string matching that breaking `"userprofile"` into three pieces makes a difference.

## Host Reconnaissance With XOR Encoding

Next comes the `chkos` routine, a basic system fingerprinting function. It grabs:

- The processor architecture (`PROCESSOR_ARCHITECTURE`)
- The Office version (`Application.Version`)
- A listing of installed programs from both `Program Files` directories

Nothing unusual there. But what's interesting is what happens to the data afterwards. The macro XOR-encodes everything with key **0x4A** (74 decimal) and then stashes the result inside a hidden textbox shape in the document itself:

```vb
bval = Asc(Mid(tmp, i, 1))
bval = bval Xor k                        ' k = 74
res = res & Chr(bval)
...
Set shp = ActiveDocument.Shapes.AddTextbox(...)
shp.Visible = msoFalse
shp.TextFrame.TextRange.Text = chk
```

The shape is created off-screen and set to invisible. It's a neat way to stage recon data inside the document without writing additional files to disk, at least initially.

## The Real Payload: A DLL Disguised as a Log File

This is where things get serious. The macro drops a **64-bit DLL** to the temp directory, but names it like an innocuous log file:

| | |
|---|---|
| **Path** | `%TEMP%\default-20241101-1112.log` |
| **SHA-256** | `c03f09eda8c19fa5c26854a81b01069454faf66e78844f61d301bebda4a09b86` |
| **True type** | Win32 DLL (64-bit) |
| **Size** | 213 KB |
| **AV detection** | 35/72 |

This DLL is the **Covenant Grunt loader**. It includes anti-analysis features including debug environment detection and long sleep calls to outlast sandbox timeouts. Our `APT_MAL_Covenant_Backdoor_Loader_Feb26` rule flagged it immediately.

On top of that, the document copies itself to `C:\Windows\jnxd4oee.exe` and creates a `.LNK` shortcut file (`document.docm.LNK`) for persistence. There's also a second dropped executable at `C:\Windows\YIhhV7n5CyvgQKK.exe`.

## Dropbox as C2 Infrastructure

Looking at the network behavior, the sample reaches out to **Dropbox** (`dropbox.com`, `162.125.248.18`). APT28 has used legitimate cloud services as dead-drop resolvers before. It lets them blend C2 traffic with normal enterprise cloud usage, making it harder for network defenders to spot.

## The Rules That Caught It

Three YARA rules from our THOR and Valhalla rule sets fired on this cluster:

- [**APT_MAL_Covenant_Backdoor_Loader_Feb26**](https://valhalla.nextron-systems.com/info/rule/APT_MAL_Covenant_Backdoor_Loader_Feb26): The key rule linking this to APT28's Covenant Grunt loader *(X__Junior, MalGamy)*
- [**Mal_Doc_Mar18_1_Mundial**](https://valhalla.nextron-systems.com/info/rule/Mal_Doc_Mar18_1_Mundial): Catches the shellcode injection into rundll32 *(Florian Roth)*
- [**SUSP_OLE_Embedded_EXE_Oct23**](https://valhalla.nextron-systems.com/info/rule/SUSP_OLE_Embedded_EXE_Oct23): Flags the embedded PE inside the OLE structure *(Paul Hager)*

The layering matters here. `SUSP_OLE_Embedded_EXE_Oct23` is a broad behavioral rule that'll catch any Office document with an embedded executable. `Mal_Doc_Mar18_1_Mundial` narrows it down to documents using the specific rundll32 injection technique. And `APT_MAL_Covenant_Backdoor_Loader_Feb26` seals the attribution by identifying the Covenant payload itself.

That's three levels of detection (generic, technique-specific, and actor-specific) all working together.

## IOCs

### File Hashes (SHA-256)

**Office Documents**
```
2d8f5187a6208fbb269abfd072663d03adffec6c77a24a5c5af31ca52778089d
74ffcff4d4618c1c3fe0c0750b391ea27383131e5340f98626afae76b69e5a6d
a14dc55a66c53315929cd8536be054296593790732c0b440fa9cdce240dfba93
d1ec65537dafbe0e6255892622464983cd890de6348b79ef1977a4b03b0f23c4
debd7a84b7b9a17765e7fe2c0f2855c49f19a4e35272e6847a87fd7438e15aa5
e20413254a149c372a43765a020b1c9abc9ba211cfc8c0fe4342c0997ee4745c
fa0e68457b06c50d41b92ecf3440b0cb0c37e6ccf1bc60039526ec1844f2ce16
```

**Covenant Grunt Loader DLL**
```
c03f09eda8c19fa5c26854a81b01069454faf66e78844f61d301bebda4a09b86
```

### Dropped Artifacts

| Path | What It Is |
|------|------------|
| `%TEMP%\default-20241101-1112.log` | Covenant Grunt loader (DLL disguised as log) |
| `C:\Windows\jnxd4oee.exe` | Self-copy of the malicious document |
| `C:\Windows\YIhhV7n5CyvgQKK.exe` | Dropped executable |
| `document.docm.LNK` | Persistence shortcut |

### Network

| Indicator | Context |
|-----------|---------|
| `dropbox.com` | C2/staging via legitimate cloud service |
| `162.125.248.18` | Dropbox infrastructure |
