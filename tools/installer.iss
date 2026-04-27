; RhinoSniff Installer — Inno Setup Script
; Build with: iscc installer.iss

#define MyAppName "RhinoSniff"
#define MyAppVersion "3.0.1"
#define MyAppExeName "RhinoSniff.exe"

; Path to dotnet publish output
#define PublishDir "RhinoSniff\bin\Release\net6.0-windows10.0.19041.0\win-x64\publish"

[Setup]
AppId={{8F3B2A1C-5D4E-4F6A-9B8C-7E2D1A3F5B6C}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} v{#MyAppVersion}
AppPublisher=Rhino
DefaultDirName={autopf}\{#MyAppName}
DisableProgramGroupPage=yes
DisableWelcomePage=yes
DisableDirPage=yes
DisableReadyPage=yes
OutputDir=installer_output
OutputBaseFilename=RhinoSniff_Setup_v{#MyAppVersion}
SetupIconFile=rhinosniff-ico.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
MinVersion=10.0
ArchitecturesInstallIn64BitMode=x64
ArchitecturesAllowed=x64

[Files]
Source: "{#PublishDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "npcap.exe"; DestDir: "{tmp}"; Flags: ignoreversion deleteafterinstall; Check: not IsNpcapInstalled
Source: "dotnet6-desktop.exe"; DestDir: "{tmp}"; Flags: ignoreversion deleteafterinstall; Check: not IsDotNet6DesktopInstalled

[Icons]
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"

[Run]
Filename: "{tmp}\dotnet6-desktop.exe"; Parameters: "/install /quiet /norestart"; StatusMsg: "Installing .NET 6 Desktop Runtime..."; Flags: waituntilterminated; Check: not IsDotNet6DesktopInstalled
Filename: "{tmp}\npcap.exe"; Parameters: "/winpcap_mode"; StatusMsg: "Installing Npcap network driver (follow the prompts)..."; Flags: waituntilterminated; Check: not IsNpcapInstalled
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent shellexec

[UninstallDelete]
Type: filesandordirs; Name: "{userappdata}\RhinoSniff"

[Code]
function IsNpcapInstalled: Boolean;
begin
  Result := RegKeyExists(HKLM, 'SOFTWARE\WOW6432Node\Npcap') or
            RegKeyExists(HKLM, 'SOFTWARE\Npcap') or
            RegKeyExists(HKLM, 'SYSTEM\CurrentControlSet\Services\npcap');
end;

// Checks whether a .NET 6 Desktop Runtime (any 6.0.x patch version) is installed by looking
// for the versioned subkey under Microsoft.WindowsDesktop.App. Uses the 64-bit view explicitly
// since we ship x64. Returns True if ANY 6.0.* version is present.
function IsDotNet6DesktopInstalled: Boolean;
var
  Names: TArrayOfString;
  i: Integer;
begin
  Result := False;
  if RegGetSubkeyNames(HKLM64,
    'SOFTWARE\dotnet\Setup\InstalledVersions\x64\sharedfx\Microsoft.WindowsDesktop.App',
    Names) then
  begin
    for i := 0 to GetArrayLength(Names) - 1 do
    begin
      if Copy(Names[i], 1, 2) = '6.' then
      begin
        Result := True;
        Exit;
      end;
    end;
  end;
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
end;
