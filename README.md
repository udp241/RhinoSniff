# RhinoSniff

```
*****************************************************
*  RhinoSniff                                        *
*  Windows packet sniffer / network analysis tool    *
*****************************************************
```

A Windows packet sniffer and network analysis tool. C# WPF (.NET 6),
modular MVVM, Material Design dark UI.

`Copyright (c) 2026 @rhino241  ·  discord.gg/nca`

## Features

- **Live packet capture** via Npcap with adapter selection, BPF
  filters, per-IP traffic counters, PCAP export
- **Game profiles** with curated filters for common online games (CoD,
  Fortnite, Apex, Warzone, Valorant, Minecraft Bedrock, Sea of Thieves,
  uTorrent, etc.)
- **GeoIP & ISP lookup** with on-disk caching
- **ARP spoofing** (bidirectional, with packet forwarding)
- **Traffic Control** via WinDivert — packet drop / delay / replay /
  reorder rules without leaving the app
- **Filter system** with presets, hotkey-bound toggles, and a 3-step
  user-filter creation wizard
- **Discord Rich Presence** — current adapter, packet count, capture
  duration shown live on your profile
- **Hotspot mode** for sharing your capture with another machine
- **Theme system** with 6 built-in dark variants and JSON theme export
- **Persistent settings** with DPAPI-protected secrets (Discord token,
  cached creds)
- **Sound alerts** on filter matches, configurable per-rule
- **Connection timeline** with per-IP first-seen / last-seen / total
  bytes
- **Logging** with severity levels, on-disk rotation, in-app viewer
- **Custom WPF DataGrid** with Region / DataIn / DataOut / Ping columns

## Requirements

To **run** RhinoSniff:

- Windows 10 build 19041 (2004) or newer, x64 only
- [.NET 6 Desktop Runtime](https://dotnet.microsoft.com/download/dotnet/6.0)
- [Npcap 1.79+](https://npcap.com/) installed in WinPcap-compatible mode
- Administrator privileges (for packet capture & ARP spoofing)

To **build** from source:

- Visual Studio 2022 (17.4+) with the `.NET desktop development` workload,
  or `dotnet` CLI 6.0+
- Optional: [Inno Setup 6](https://jrsoftware.org/isinfo.php) if you
  want to build the installer

## Build

From the repo root:

```bat
build.bat
```

That runs `dotnet restore` then `dotnet publish RhinoSniff.sln -c Release
-r win-x64 --self-contained true`. The output lands in:

```
RhinoSniff\bin\Release\net6.0-windows10.0.19041.0\win-x64\publish\
```

To run, copy the **entire** `publish` folder somewhere — `RhinoSniff.exe`
needs the DLLs sitting next to it.

### WinDivert (optional — for Traffic Control)

The Traffic Control feature requires the WinDivert kernel driver.
WinDivert is **not bundled** in this repo. Download from:

- https://reqrypt.org/windivert.html

Drop `WinDivert.dll` and `WinDivert64.sys` into the **repo root** (next
to `RhinoSniff.sln`). The build will pick them up via the
`Condition="Exists(...)"` rules in `RhinoSniff.csproj` and copy them
to the output directory automatically. Without these files, packet
capture and other features still work — only Traffic Control is
disabled.

### Building the installer

```bat
cd tools
build_installer.bat
```

This runs the Inno Setup compiler against `tools/installer.iss`. The
script bundles the dotnet 6 desktop runtime and Npcap installers if
they're present alongside the .iss — download them separately:

- https://dotnet.microsoft.com/download/dotnet/6.0/runtime  →  save as `dotnet6-desktop.exe`
- https://npcap.com/dist/npcap-1.87.exe  →  save as `npcap.exe`

The output `.exe` lands in `tools/installer_output/`.

## Project structure

```
RhinoSniff/
├── RhinoSniff.sln           solution file
├── build.bat                one-shot publish script
├── RhinoSniff/              main project (WPF, .NET 6)
│   ├── RhinoSniff.csproj
│   ├── App.xaml(.cs)
│   ├── AssemblyInfo.cs
│   ├── Globals.cs
│   ├── app.manifest
│   ├── rhinosniff-ico.ico
│   ├── Models/              data classes (Settings, Theme, packet
│   │                        wrappers, GeoIP cache, filter presets,
│   │                        ARP, hotkeys, RPC config, ...)
│   ├── Views/               WPF user controls (sidebar pages)
│   ├── Windows/             top-level windows (Main, About, ...)
│   ├── Classes/             services & managers (capture, filter,
│   │                        ARP, geoip, settings, theme, RPC,
│   │                        traffic control, breathing border, ...)
│   ├── Converters/          XAML value converters
│   ├── Interfaces/          service contracts
│   ├── Properties/          assembly props
│   └── Resources/           icons, fonts, themes, images
└── tools/
    ├── installer.iss        Inno Setup script
    └── build_installer.bat  one-shot installer build
```

## Brand consistency

Shares its visual identity with the rest of the Rhino tool family
(rhino-multi-tool, RhinoSSH, RhinoGPS, isp / icmp / paping / nsl,
rhino-selfbot):

- Cyan accent (256-color 51) + 6 theme palette
- `Copyright (c) 2026 @rhino241`
- Window title `RhinoSniff v3.0.x`
- Persistent settings + DPAPI-protected secrets
- Discord Rich Presence with the same field structure as rhino-selfbot's
  RPC system
- Breathing accent border (Win11+) — algorithm shared verbatim with
  rhino-multi-tool's `BreathingBorderManager`

---

`discord.gg/nca`  ·  `t.me/ncaheadquarters`  ·  `@rhino241`
