# A .NET Variant of the WebSockets Backdoor Downloader

## Introduction

On October 14, [dmpdump published a detailed analysis](https://dmpdump.github.io/posts/websocketsbackdoor/) of a downloader and WebSockets backdoor targeting Iraq. The downloader, `document.exe`, is a native C++ binary that goes through some effort to stay hidden - it resolves APIs by walking the PEB, hashes function names with FNV-1a to avoid plaintext imports, and XOR-encrypts all of its strings with key `0x5A`. It downloads a backdoor and its dependencies from a hardcoded IP, then hands off execution to `nvcontainer.exe`, a WebSocket-based implant used for drive reconnaissance and data exfiltration.

While investigating this campaign, we came across a second downloader targeting the same infrastructure. This one is written in .NET 8 and takes a very different approach to stealth: there is none. Every string - the C2 IP, the mutex name, the drop path, the file URLs - sits in the binary in plaintext. Yet the sample still does something the native variant does not: it ships as a self-contained single-file .NET application, bundling the entire CoreCLR runtime into one executable. This means it runs on any Windows machine without requiring .NET to be installed, and it buries the managed code (where all the interesting strings live) inside a native host binary that IDA sees as nothing but runtime internals.

We reversed the sample entirely through static analysis in dnSpy. We did not execute it or contact its infrastructure.

## Key Findings

- .NET 8 variant of the downloader documented by dmpdump, targeting the same payload server (`153.75.247[.]94`) and downloading the exact same seven files
- Deployed as a self-contained single-file executable (~14 MB), embedding the CoreCLR runtime alongside the 23 KB managed assembly - no .NET installation required on the victim
- Zero obfuscation: all URLs, paths, and identifiers are in plaintext, in contrast to the native variant's XOR-encrypted strings and PEB-based API resolution
- Significantly more resilient download logic: HTTP Range resume, parallel downloads, 50 retries with exponential backoff, and a 3-hour wait for fast internet
- Shares the `54321` mutex suffix with the native variant, confirming a common developer

## Sample Overview

| Field | Value |
|---|---|
| SHA256 (managed DLL) | `7a0ce15051cf82cfb107d94dd4a16d55ee18783e2577b434d268799db8f843c9` |
| SHA256 (single-file host) | `d172138487a2e66398c7474e24849dbf19157bb30823de7df98556943de7f74f` |
| File type | .NET 8.0, x64, self-contained single-file |
| Managed assembly size | 23,552 bytes |
| Deployed size | ~14 MB (includes CoreCLR runtime) |
| Obfuscation | None |
| Entry point | `Program.Main` |

## Packaging: A Single-File .NET App

The sample we obtained on disk was a ~14 MB executable with no file extension. Opening it in IDA, we initially saw thousands of functions - `PgoManager`, `ProfilingAPIDetach`, `BaseDomain`, `SystemDomain` - all internal CoreCLR runtime symbols. No campaign strings were visible anywhere in IDA's string table. No references to NVIDIA, no URLs, no mutex names.

The PDB path embedded in the binary gave it away:

```
D:\a\_work\1\s\artifacts\obj\coreclr\windows.x64.Release\Corehost.Static\singlefilehost.pdb
```

Along with the `BUNDLE_PROBE` and `HOSTPOLICY_EMBEDDED` strings, this told us we were looking at a .NET single-file deployment - the .NET SDK's `dotnet publish` with `/p:PublishSingleFile=true` produces exactly this kind of binary. The native host is just a launcher; the actual application logic lives in a bundle appended to the end of the file.

Reading the last 2 KB of the binary confirmed it. The bundle manifest listed the embedded files:

```
Dper.runtimeconfig.json
Dper.dll                           ← the actual malware (23 KB)
Microsoft.Win32.Registry.dll
System.Collections.dll
System.Console.dll
System.Net.Http.dll
System.Net.Ping.dll
System.Private.CoreLib.dll
...
```

The 23 KB `Dper.dll` is the only file that matters. Everything else is the .NET runtime and its standard libraries. We extracted `Dper.dll` from the bundle and loaded it into dnSpy for analysis.

This packaging choice has a practical side effect for detection: native analysis tools like IDA only see the CoreCLR runtime code. The malware's actual strings and logic are in the managed metadata heap, invisible to tools that parse PE strings or native code. A string-based YARA rule looking for `153.75.247` in the native host binary will not match - that string only exists in the embedded .NET assembly's User Strings (#US) metadata stream.

## Execution Flow

### Mutex and Window Hiding

The first thing the downloader does is create a global mutex and hide its console window:

```csharp
using (new Mutex(true, "Global\\Nvidia_Container_Downloader_Unique_ID_54321", ref flag))
{
    if (flag)
    {
        ShowWindow(GetConsoleWindow(), 0);
```

The mutex name is remarkably verbose - it spells out the tool's purpose in plain English. Compare this with the native variant's `Global\NvCDIr_U54321`, which abbreviates everything. The shared `54321` suffix across both variants is a strong link to the same developer.

### Randomized Delays

The downloader calls a `QuickDelay()` function at least six times throughout execution - before checking the status file, before creating directories, before writing completion markers, and before launching the payload:

```csharp
public static Task QuickDelay()
{
    int delay;
    lock (_lockObject)
    {
        delay = _random.Next(1000, 10000);
    }
    await Task.Delay(delay);
}
```

Each call sleeps for a random 1–10 seconds. In an automated sandbox with a short execution timeout, this could mean the downloader spends most of its allotted time sleeping and never reaches the download stage. Against static analysis, of course, it does nothing.

### Checking for Previous Runs

Before downloading anything, the downloader checks a status file at `%TEMP%\nvidia_download_status.dat`:

```csharp
if (File.Exists(statusFile) && File.ReadAllText(statusFile) == "COMPLETED")
{
    if (File.Exists(exePath))
        Process.Start(exePath);
    _downloadCompleted = true;
    return;
}
```

If a previous run already completed the download, the downloader skips straight to launching the payload. This lets it double as a simple persistence mechanism - on reboot, it re-launches `nvcontainer.exe` without hitting the network again.

### The Download List

The downloader builds a hardcoded list of seven files to fetch from `http://153.75.247[.]94`. Each file is hosted under an image extension but saved with its real extension:

| File on Server | Saved As | What It Is |
|---|---|---|
| `/libcrypto-3-x64.jpg` | `libcrypto-3-x64.dll` | OpenSSL crypto library |
| `/libssl-3-x64.jpg` | `libssl-3-x64.dll` | OpenSSL SSL/TLS library |
| `/ucrtbased.jpg` | `ucrtbased.dll` | Universal C Runtime (Debug build) |
| `/vcruntime140D.jpg` | `vcruntime140D.dll` | VC++ Runtime (Debug build) |
| `/websockets.jpg` | `websockets.dll` | libwebsockets |
| `/cacert.jpg` | `cacert.pem` | CA certificate bundle |
| `/nvcontainer.png` | `nvcontainer.exe` | The backdoor |

This is the exact same file set that dmpdump documented for the native variant - same server, same filenames, same extensions. The image-extension trick is presumably meant to look like normal web traffic at a glance, or to bypass basic network filters that block `.exe` and `.dll` downloads.

Two of the dropped DLLs - `ucrtbased.dll` and `vcruntime140D.dll` - are debug builds (the `d` / `D` suffix). This tells us the backdoor was compiled in Debug configuration, which is unusual for production malware and suggests the developer may not have a polished build pipeline.

Everything gets dropped to:

```
C:\Users\<username>\AppData\Roaming\Microssoft\Cache\
```

Note the typo: "Microssoft" with a double 's'. The native variant uses a different path entirely (`AppData\Roaming\Microsoft\Protect\NV`), but both try to blend into the `AppData\Roaming` landscape.

### How the Downloads Work

Before downloading, the downloader sends HTTP HEAD requests to get each file's size. Then it enters the main download loop, which is where this variant really differs from its native counterpart.

Downloads run in parallel, three at a time, controlled by a semaphore:

```csharp
var semaphore = new SemaphoreSlim(3);
```

Each individual file download supports HTTP Range-based resume. If a previous attempt was interrupted, the downloader picks up where it left off:

```csharp
if (existingSize > 0L && existingSize < expectedSize)
{
    request.Headers.Range = new RangeHeaderValue(existingSize, null);
}
```

Progress is tracked in `%TEMP%\nvidia_download_progress.dat` as simple `filename=bytesdownloaded` pairs, so resume works across process restarts.

The retry logic is aggressive. Each file retries up to 5 times with linear backoff (2s, 4s, 6s, 8s, 10s). The overall download loop retries up to 50 times with exponential backoff capped at 60 seconds. And before each attempt, the downloader checks whether the internet is fast enough by pinging `8.8.8.8`:

```csharp
private static bool IsInternetFast()
{
    using (Ping ping = new Ping())
    {
        PingReply reply = ping.Send("8.8.8.8", 2000);
        return reply.Status == IPStatus.Success && reply.RoundtripTime < 500L;
    }
}
```

If the connection is slow, the downloader waits - for up to three hours - polling every 5 seconds until latency drops below 500ms. It also subscribes to `NetworkChange.NetworkAvailabilityChanged` events so it knows when connectivity comes back after a network drop.

A file is considered complete when it reaches 95% of the expected size. This is a curious threshold - it likely accounts for differences between the Content-Length reported by the server and the actual bytes received due to encoding or connection issues.

The HTTP client itself uses a truncated User-Agent:

```
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
```

A real browser would continue with `(KHTML, like Gecko) Chrome/... Safari/...`. The native variant uses this same truncated string for its GET requests, another link between the two.

### Launching the Payload

Once all files are down, the downloader writes `COMPLETED` to the status file and starts `nvcontainer.exe`:

```csharp
File.WriteAllText(statusFile, "COMPLETED");
if (File.Exists(exePath))
    Process.Start(exePath);
_downloadCompleted = true;
```

There is no fallback here. The native variant tries `CreateProcessA`, falls back to `ShellExecuteA`, copies files to a temp directory and tries again - the .NET version just calls `Process.Start()` once. It also skips removing the Mark of the Web (the `Zone.Identifier` alternate data stream), which the native variant deletes before execution.

### Cleanup

After the download completes, the downloader removes its tracks:

```csharp
// Deleted files:
%TEMP%\download_status.dat
%TEMP%\download_progress.dat
%TEMP%\Nvidia container_error.txt
C:\ProgramData\error_log.txt
%APPDATA%\Microssoft\Cache\download.log
%TEMP%\Nvidia_container_*.tmp

// Deleted registry key:
HKCU\SOFTWARE\Nvidia containerDownloader
```

Some of these paths - like the `ProgramData\error_log.txt` and the registry key - are not created anywhere in the downloader's own code. They may be artifacts from the backdoor, or leftovers from an earlier version of the tooling. The cleanup is best-effort: each deletion is wrapped in a try/catch that silently ignores failures.

### Preventing Termination

The downloader also installs a console control handler that blocks process termination while the download is still running:

```csharp
private static bool Handler(CtrlTypes ctrlType)
{
    return (ctrlType == CtrlTypes.CTRL_CLOSE_EVENT
        || ctrlType - CtrlTypes.CTRL_LOGOFF_EVENT <= 1)
        && !_downloadCompleted;
}
```

Returning `true` tells Windows not to terminate the process. This covers console close, user logoff, and system shutdown - the downloader will keep running through all of them until the download finishes.

## Comparison with the Native Variant

| | Dper.dll (.NET) | document.exe (Native) |
|---|---|---|
| **Language** | .NET 8, C# | MSVC, C++ |
| **Deployment** | Self-contained single-file (~14 MB) | Standalone PE (~??? KB) |
| **String protection** | None | XOR, key `0x5A` |
| **API resolution** | Standard .NET APIs | PEB walk + FNV-1a hash |
| **C2 IP** | `153.75.247[.]94` | `153.75.247[.]94` |
| **Payload files** | Same 7 files | Same 7 files |
| **Drop path** | `%APPDATA%\Microssoft\Cache\` | `%APPDATA%\Microsoft\Protect\NV` |
| **Mutex** | `Global\Nvidia_Container_Downloader_Unique_ID_54321` | `Global\NvCDIr_U54321` |
| **Internet check** | ICMP ping to `8.8.8.8` (< 500ms RTT) | WinHTTP connect to `google.com` (no request sent) |
| **Downloads** | HttpClient, async, 3 parallel, Range resume | WinHTTP API, threaded |
| **Retries** | 50x overall + 5x per file, exponential backoff | Basic |
| **Internet wait** | Up to 3 hours | None |
| **MoTW removal** | No | Yes |
| **Exec fallback** | `Process.Start()` only | CreateProcessA -> ShellExecuteA -> temp copy |

The two variants clearly come from the same developer: the infrastructure is identical, the file set is identical, the mutex names share a suffix, and both use the same truncated User-Agent string. But they represent different design priorities. The native variant invests in stealth - encrypted strings, manual API resolution, Zone.Identifier removal, multiple execution fallbacks. The .NET variant invests in reliability - resume support, aggressive retries, long waits for connectivity, parallel downloads. 

One possible explanation: the .NET variant targets environments where the native one kept failing to complete the download (slow or unstable connections), and the developer decided that getting the payload delivered mattered more than hiding the downloader's intent.

## The Backdoor

The downloaded `nvcontainer.exe` is a WebSocket-based backdoor that connects to `www.xionamiconm[.]com:8050/ws/`. As dmpdump documented, it supports drive enumeration, directory listing, file download, and file exfiltration. The inclusion of OpenSSL libraries, a CA certificate bundle, and a libwebsockets DLL alongside the executable confirms that the backdoor establishes encrypted WebSocket connections for its C2 channel. The use of debug CRT libraries suggests the developer has not yet moved to release builds.

For a full analysis of the backdoor's capabilities and command set, see [dmpdump's report](https://dmpdump.github.io/posts/websocketsbackdoor/).

## Indicators of Compromise

### File Indicators

| Type | Value |
|---|---|
| SHA256 (Dper.dll, managed assembly) | `7a0ce15051cf82cfb107d94dd4a16d55ee18783e2577b434d268799db8f843c9` |
| SHA256 (self-contained single-file host) | `d172138487a2e66398c7474e24849dbf19157bb30823de7df98556943de7f74f` |

### Network Indicators

| Type | Value |
|---|---|
| Payload server | `153.75.247[.]94` (HTTP, port 80) |
| Backdoor C2 | `www.xionamiconm[.]com:8050/ws/` |

### Host Indicators

| Type | Value |
|---|---|
| Mutex | `Global\Nvidia_Container_Downloader_Unique_ID_54321` |
| Drop directory | `%APPDATA%\Microssoft\Cache\` |
| Payload | `%APPDATA%\Microssoft\Cache\nvcontainer.exe` |
| Status file | `%TEMP%\nvidia_download_status.dat` |
| Progress file | `%TEMP%\nvidia_download_progress.dat` |
| Error log | `%TEMP%\Nvidia container_error.txt` |
| Registry key | `HKCU\SOFTWARE\Nvidia containerDownloader` |
| User-Agent | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36` |

### Downloaded Files

| Remote Path | Local Name |
|---|---|
| `/libcrypto-3-x64.jpg` | `libcrypto-3-x64.dll` |
| `/libssl-3-x64.jpg` | `libssl-3-x64.dll` |
| `/ucrtbased.jpg` | `ucrtbased.dll` |
| `/vcruntime140D.jpg` | `vcruntime140D.dll` |
| `/websockets.jpg` | `websockets.dll` |
| `/cacert.jpg` | `cacert.pem` |
| `/nvcontainer.png` | `nvcontainer.exe` |

## References

- dmpdump, "[New WebSockets Backdoor Likely Targeting Iraq](https://dmpdump.github.io/posts/websocketsbackdoor/)", October 2026
