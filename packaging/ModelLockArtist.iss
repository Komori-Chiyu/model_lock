; 星零集模型锁-画师端 installer
#define AppName "星零集模型锁-画师端"
#define AppExe "ModelLockArtist.exe"

[Setup]
AppId={{8A3E2B0D-4C21-4E7F-9A5D-3C9D2B0F0002}}
AppName={#AppName}
AppVersion=0.1.0
DefaultDirName={autopf}\ModelLockArtist
DefaultGroupName=星零集模型锁
OutputDir=output
OutputBaseFilename=ModelLockArtist-Setup
Compression=lzma2
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible

[Files]
Source: "..\dist\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "附加任务:"

[Run]
Filename: "{app}\{#AppExe}"; Description: "启动 {#AppName}"; Flags: nowait postinstall skipifsilent
