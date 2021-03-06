; Script generated by the Inno Setup Script Wizard.
; SEE THE DOCUMENTATION FOR DETAILS ON CREATING INNO SETUP SCRIPT FILES!

#define MyAppName "oxd-server"
#define MyAppVersion "4.2"
#define MyAppPublisher "Gluu, Inc."
#define MyAppURL "https://www.gluu.org/"
#define MyAppExeName "oxd-server.exe"
;set path to jre home
#define JREHome GetEnv('JRE_HOME')
;set path of the instructions to run oxd server
#define OXDInstructionFile "..\license\license.txt"
;set path to output directory of the exe file
#define OXDExeOutputDir "..\"
;set path to oxd-server project.build.directory
#define OXDTargetDir "..\"


[Setup]
; NOTE: The value of AppId uniquely identifies this application.
; Do not use the same AppId value in installers for other applications.
; (To generate a new GUID, click Tools | Generate GUID inside the IDE.)
AppId={{F23E1E34-794C-4817-9E58-D2627626CBF1}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
;AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={pf}\{#MyAppName}
;DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
;InfoBeforeFile={#OXDInstructionFile}
LicenseFile={#OXDInstructionFile}
OutputDir={#OXDExeOutputDir}
OutputBaseFilename=oxd-server
Compression=lzma
SolidCompression=yes
DisableDirPage=no
ChangesEnvironment=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
;Source: "{#OXDTargetDir}oxd-server.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#OXDTargetDir}bin\*"; DestDir: "{app}\bin"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#OXDTargetDir}conf\generate-exe-using-bat.iss"; DestDir: "{app}\conf"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#OXDTargetDir}conf\oxd-server.keystore"; DestDir: "{app}\conf"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#OXDTargetDir}conf\oxd-server-win.yml"; DestDir: "{app}\conf"; DestName: "oxd-server.yml"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#OXDTargetDir}lib\*"; DestDir: "{app}\lib"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#OXDTargetDir}license\*"; DestDir: "{app}\license"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#JREHome}\*"; DestDir: "{app}\jre"; Flags: ignoreversion recursesubdirs createallsubdirs
; NOTE: Don't use "Flags: ignoreversion" on any shared system files

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"

[Registry]
Root: HKCU; Subkey: "Environment"; ValueType:string; ValueName: "OXD_HOME"; ValueData: {app}; Flags: preservestringtype

[Run]
Filename: "{app}\bin\oxd-service-install.bat"; Check: InstallAsServiceFile;

[UninstallRun]
Filename: "{app}\bin\oxd-service-uninstall.bat"; Flags: runhidden

[Code]
var
  InstallAsServiceCheckBox: TNewCheckBox;

procedure InitializeWizard;
var
 
  StaticText1: TNewStaticText;
  MainPage: TWizardPage;  
  Panel: TPanel;

begin
  MainPage := CreateCustomPage(wpWelcome, 'Do you want to install oxd as service?', 'Select the checkbox to install oxd as service.');

  //panel
  Panel := TPanel.Create(MainPage);
  Panel.Parent := MainPage.Surface;
  Panel.Left := 10;
  Panel.Top := 50;
  Panel.Width := ScaleX(450);
  Panel.Height := ScaleX(250);
  Panel.Visible := True;
  //text
  StaticText1 := TNewStaticText.Create(MainPage);
  StaticText1.Parent := Panel;
  StaticText1.Left := 12;
  StaticText1.Top := 50;
  StaticText1.Width := ScaleX(417);
  StaticText1.WordWrap:= true;
  StaticText1.Caption := 'Select the below checkbox to install oxd-server as windows service.';

  //checkbox
  InstallAsServiceCheckBox := TNewCheckBox.Create(MainPage);
  InstallAsServiceCheckBox.Parent := Panel;
  InstallAsServiceCheckBox.Top := 75;
  InstallAsServiceCheckBox.Left := 85;
  InstallAsServiceCheckBox.Width := ScaleX(417);
  InstallAsServiceCheckBox.Caption := 'Install OXD as service';
  //set installation directory blank
  WizardForm.DirEdit.Text := '';
end;

function InstallAsServiceFile: Boolean;
begin
  // here is the Check function used above; if you return True to this
  // function, the file will be installed, when False, the file won't 
  // be installed
  Result := InstallAsServiceCheckBox.Checked;
end;