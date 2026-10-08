; Установщик WebNetCheck (Inno Setup 6).
;
; Сборка (после build_exe.bat):
;   ISCC.exe /DAppVersion=1.2.0 installer\webnetcheck.iss
; Результат: dist\WebNetCheck-<версия>-setup.exe
;
; По умолчанию ставится для текущего пользователя без прав администратора
; (%LOCALAPPDATA%\Programs\WebNetCheck); в мастере можно выбрать установку для всех.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef GuiDir
  #define GuiDir "..\dist\WebNetCheck"
#endif
#ifndef CliDir
  #define CliDir "..\dist\webnetcheck-cli"
#endif

[Setup]
; AppId не менять: по нему установщик находит прошлую версию для обновления и удаления
AppId={{3B09A6B6-B495-4FE7-B0C8-4461AE0C35B7}
AppName=WebNetCheck
AppVersion={#AppVersion}
AppVerName=WebNetCheck {#AppVersion}
AppPublisher=salilov95
AppPublisherURL=https://github.com/salilov95/WebNetCheck
AppSupportURL=https://github.com/salilov95/WebNetCheck/issues
AppUpdatesURL=https://github.com/salilov95/WebNetCheck/releases
DefaultDirName={autopf}\WebNetCheck
DefaultGroupName=WebNetCheck
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
LicenseFile=..\LICENSE
SetupIconFile=..\assets\webnetcheck.ico
UninstallDisplayIcon={app}\WebNetCheck.exe
UninstallDisplayName=WebNetCheck {#AppVersion}
OutputDir=..\dist
OutputBaseFilename=WebNetCheck-{#AppVersion}-setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
VersionInfoVersion={#AppVersion}
VersionInfoDescription=WebNetCheck Setup

[Languages]
Name: "ru"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
ru.CompMain=Программа WebNetCheck (окно)
en.CompMain=WebNetCheck application (GUI)
ru.CompCli=Консольная версия webnetcheck-cli
en.CompCli=Console version webnetcheck-cli
ru.TypeFull=Полная установка
en.TypeFull=Full installation
ru.TypeCustom=Выборочная установка
en.TypeCustom=Custom installation

[Types]
Name: "full"; Description: "{cm:TypeFull}"
Name: "custom"; Description: "{cm:TypeCustom}"; Flags: iscustom

[Components]
Name: "main"; Description: "{cm:CompMain}"; Types: full custom; Flags: fixed
Name: "cli"; Description: "{cm:CompCli}"; Types: full

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#GuiDir}\*"; DestDir: "{app}"; Components: main; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#CliDir}\*"; DestDir: "{app}\cli"; Components: cli; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\WebNetCheck"; Filename: "{app}\WebNetCheck.exe"
Name: "{group}\{cm:UninstallProgram,WebNetCheck}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\WebNetCheck"; Filename: "{app}\WebNetCheck.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\WebNetCheck.exe"; Description: "{cm:LaunchProgram,WebNetCheck}"; Flags: nowait postinstall skipifsilent
