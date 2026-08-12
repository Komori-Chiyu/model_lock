; ModelLock Buyer Client installer
#define AppName "ModelLock 买家端"
#define AppExe "modelock-client-ui.exe"

[Setup]
AppId={{8A3E2B0D-4C21-4E7F-9A5D-3C9D2B0F0001}}
AppName={#AppName}
AppVersion=0.1.0
DefaultDirName={autopf}\ModelLockClient
DefaultGroupName=ModelLock
OutputDir=output
OutputBaseFilename=ModelLockClient-Setup
Compression=lzma2
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible

[Files]
Source: "..\client-ui\target\release\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
; Dokan v2 runtime (dokan2.dll + kernel driver): required to mount .vkit volumes.
Source: "redist\Dokan_x64.msi"; DestDir: "{app}\redist"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "附加任务:"

[Run]
; Silently install the Dokan runtime before first launch (skipped if already installed).
Filename: "{sys}\msiexec.exe"; Parameters: "/qn /norestart /i ""{app}\redist\Dokan_x64.msi"""; \
    StatusMsg: "正在安装 Dokan 文件系统运行时..."; \
    Flags: runhidden waituntilterminated; Check: not DokanInstalled
Filename: "{app}\{#AppExe}"; Description: "启动 {#AppName}"; Flags: nowait postinstall skipifsilent

[Code]
function DokanInstalled: Boolean;
begin
  // dokan2.dll in System32 means the Dokan v2 runtime (user-mode DLL +
  // kernel driver) is present on this machine.
  Result := FileExists(ExpandConstant('{sys}\dokan2.dll'));
end;
