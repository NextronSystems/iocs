# Ukraine-Targeted Campaign Using a Telegram-Controlled VBScript RAT

## Summary

We analyzed a Ukraine-targeted infection chain that ends in a Telegram-controlled VBScript RAT.

The initial access document led us to a second weaponized file from the same campaign, pushing the observed activity back to late August 2026.

The two documents use very different lure themes:

* `ПОВІТРЯНА ТРИВОГА.docm` - Ukrainian for "air raid alert", first submitted from Ukraine on 2026-09-16
* `МайноНРКнапідрозділахстаномна25_08_2026_23.xlsm` - a materiel inventory held at subunits, current as of 25.08.2026, first seen on 2026-08-26

The first lure plays directly on wartime civil defence alerting and could appeal to a broad Ukrainian audience.

The second is much more specific. `підрозділ` is standard Ukrainian military terminology, and the filename refers to property or materiel held by military subunits. The file was uploaded only one day after the date contained in its filename.

Together, the lures suggest a campaign that combines broad Ukraine-focused targeting with more specific military-oriented targeting.

## Initial Access

The analyzed Word document executes its macro through `Document_Open`.

Until macros are enabled, the document body remains scrambled. The macro reconstructs the document content using document variables and simple rotation ciphers, with the functions `ScrambleWord` and `UnscrambleWord` restoring the text after the user clicks "Enable Content".

The macro then calls `DownloadAndRunGoogleDoc`, which downloads the next stage from GitHub raw hosting using `MSXML2.XMLHTTP`.

The payload is written to `%TEMP%` using `ADODB.Stream`.

It is saved as:

```text
Microsoft Excel.dll
```

Despite the `.dll` extension, the file is not a PE executable.

Instead, it is launched as VBScript using:

```text
wscript.exe //E:VBScript
```

The script is executed in a hidden window, making the file extension irrelevant to execution.

## VBScript Payload

The staged payload is an obfuscated VBScript RAT.

Its main body is stored in 978 hex-encoded chunks. These are decoded to UTF-16LE using `MSXML2.DOMDocument` with `bin.hex` together with `ADODB.Stream`.

The loader removes the BOM and the leading `Option Explicit` statement before passing the decoded script to `ExecuteGlobal`.

Once decoded, the payload consists of:

* 2,667 lines
* 74 procedures

## Command and Control

The malware uses the Telegram Bot API for command and control.

Three Telegram bot tokens are hardcoded into the script. The malware rotates between them when Telegram returns HTTP status codes:

* `401`
* `403`
* `404`

Victims are identified using the BIOS serial number obtained through:

```text
wmic bios get serialnumber
```

Commands can be addressed to an individual host using this serial number.

The operator can also use an `ALL` broadcast to send commands to every connected victim.

This design allows the operator to manage multiple infected systems through the same Telegram-based infrastructure.

## Persistence

The malware establishes persistence through several mechanisms.

### Hidden copy

A copy of the script is stored at:

```text
%APPDATA%\SysMonPort\SysMonPort.vbs
```

The file is assigned the hidden, system and read-only attributes:

```text
+h +s +r
```

### Registry Run key

The malware creates an `HKCU` Run key to execute the script at logon.

### Startup folder

A startup stub is placed in the user's Startup folder.

### Scheduled task

The malware creates a scheduled task named:

```text
SysMonPort
```

If task creation fails at the current user level, the script retries using:

```text
/RU SYSTEM /RL HIGHEST
```

## Credential and Session Theft

The RAT targets credentials and cookies from multiple Chromium-based and Firefox-based browsers.

Supported browsers include:

* Google Chrome
* Microsoft Edge
* Brave
* Opera
* Opera GX
* Vivaldi
* Yandex
* Firefox

The malware also targets Telegram Desktop.

It collects the victim's Telegram `tdata` directory and subsequently deletes the local Telegram session from the victim system.

## Remote Access Capabilities

The RAT provides several capabilities for interactive access to compromised systems.

### Screenshots

Screenshots are captured through PowerShell using:

```text
SendKeys {PRTSC}
```

### Command execution

The operator can execute arbitrary commands through dropped PowerShell scripts.

### TCP listener

The malware can open a TCP listener on the victim system.

When doing so, it also creates a corresponding Windows Firewall rule using:

```text
netsh advfirewall
```

## File Collection

The file harvesting component targets an unusual collection of file formats.

The default extension list includes CAD, BIM, GIS, LiDAR and geospatial data:

```text
.dwg
.dxf
.dgn
.rvt
.shp
.kml
.kmz
.geotiff
.las
.laz
.e57
.ptx
.pts
```

The malware also targets:

* NetCDF files
* GRIB weather-model files

This collection profile is notable because it focuses heavily on engineering, mapping, terrain, point-cloud and weather data.

We found no cryptocurrency wallet-stealing functionality in the sample.

## Date-Based Collection

The file discovery module accepts an optional date filter in the format:

```text
dd.MM.yyyy
```

The filter is applied to `LastWriteTime`.

This allows the operator to retrieve only files that have changed since a specified date, rather than repeatedly collecting all matching files.

Combined with BIOS-serial-based host addressing, this gives the operator a way to manage a larger set of compromised hosts and perform targeted collection from selected systems.

## Targeting Observations

The two known lure documents sit at very different ends of the targeting spectrum.

`ПОВІТРЯНА ТРИВОГА.docm` uses an "air raid alert" theme that could plausibly reach a broad Ukrainian audience.

`МайноНРКнапідрозділахстаномна25_08_2026_23.xlsm` uses terminology and subject matter much more specific to military personnel handling unit property or materiel records.

The combination of broad and role-specific lures, host-specific tasking and selective file collection suggests tooling designed to maintain access to multiple systems while allowing the operator to identify and prioritize hosts of interest.

The collection of CAD, BIM, GIS, LiDAR and weather-model formats further distinguishes the activity from typical commodity credential-stealing malware.

## Samples

```text
2b86f53965e6bf5ae33658293d3977894c8f31d7a86df9c24a677e020af0a3a3
2edb9dd4df9c8ebe605fd5807b94d472392ea95b0cb6a517b659d10192f83c80
523f21fad7e3e8c4ffd9897b875c0df9609a825fd0c9d274319da132fa358cb9
```
