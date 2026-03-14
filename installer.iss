; Log Sentinel v2.0 - Inno Setup Script
; ======================================
; Cria instalador gráfico para Windows
;
; COMO USAR:
; 1. Primeiro cria o executável: python build_exe.py
; 2. Instala Inno Setup: https://jrsoftware.org/isinfo.php
; 3. Abre este ficheiro no Inno Setup Compiler
; 4. Clica em Build > Compile
; 5. O instalador será criado em Output/
;
; Author: Duarte Cunha (Nº 2024271)
; ISTEC - 2025/2026

#define MyAppName "Log Sentinel"
#define MyAppVersion "2.0"
#define MyAppPublisher "Duarte Cunha - ISTEC"
#define MyAppURL "https://istec.pt"
#define MyAppExeName "LogSentinel.exe"

[Setup]
; Informações do instalador
AppId={{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}

; Diretórios
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
OutputDir=installer_output
OutputBaseFilename=LogSentinel_Setup_v2.0

; Compressão
Compression=lzma2/ultra64
SolidCompression=yes

; Aparência
WizardStyle=modern
SetupIconFile=assets\icons\owl_logo.ico
UninstallDisplayIcon={app}\{#MyAppExeName}

; Requisitos
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog

; Outras opções
DisableProgramGroupPage=yes
LicenseFile=
InfoBeforeFile=
InfoAfterFile=

[Languages]
Name: "portuguese"; MessagesFile: "compiler:Languages\Portuguese.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
portuguese.WelcomeLabel1=Bem-vindo ao Assistente de Instalação do Log Sentinel
portuguese.WelcomeLabel2=Este assistente irá instalar o [name/ver] no seu computador.%n%nÉ recomendado que feche todas as outras aplicações antes de continuar.
portuguese.FinishedHeadingLabel=Instalação do Log Sentinel Concluída
portuguese.FinishedLabel=O Log Sentinel foi instalado com sucesso no seu computador.%n%nClique em Concluir para fechar o assistente.

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "quicklaunchicon"; Description: "{cm:CreateQuickLaunchIcon}"; GroupDescription: "{cm:AdditionalIcons}"; OnlyBelowVersion: 6.1; Check: not IsAdminInstallMode

[Files]
; Executável principal (da pasta dist após build)
Source: "dist\LogSentinel.exe"; DestDir: "{app}"; Flags: ignoreversion

; Ou se for pasta (onedir):
; Source: "dist\LogSentinel\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

; Logs de exemplo
Source: "data\logs\*"; DestDir: "{app}\data\logs"; Flags: ignoreversion recursesubdirs createallsubdirs

; Ícone
Source: "assets\icons\owl_logo.ico"; DestDir: "{app}"; Flags: ignoreversion

; README
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
; Criar pastas necessárias
Name: "{app}\data\logs"
Name: "{app}\data\models"
Name: "{app}\data\reports"

[Icons]
; Atalhos
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\owl_logo.ico"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\owl_logo.ico"; Tasks: desktopicon
Name: "{userappdata}\Microsoft\Internet Explorer\Quick Launch\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: quicklaunchicon

[Run]
; Opção para executar após instalação
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[Code]
// Código Pascal para personalização adicional

function InitializeSetup(): Boolean;
begin
  Result := True;
  // Verificações adicionais podem ser adicionadas aqui
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    // Ações pós-instalação
  end;
end;
