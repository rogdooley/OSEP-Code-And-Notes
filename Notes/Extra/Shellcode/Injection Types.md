
Injection techniques in Windows allow an attacker to execute code within the address space of another process. This can be used for various purposes, such as hiding malicious code, bypassing security controls, or gaining elevated privileges. Below is a detailed overview of the most common injection techniques, the required Win32 libraries, and the necessary privileges.

### 1. **DLL Injection**

**Description**: DLL injection involves inserting a dynamic link library (DLL) into the address space of a target process and executing code within the context of that process.

- **Win32 APIs**:
  - `OpenProcess`: Opens a handle to the target process.
  - `VirtualAllocEx`: Allocates memory in the target process.
  - `WriteProcessMemory`: Writes the DLL path into the allocated memory.
  - `CreateRemoteThread` / `NtCreateThreadEx`: Creates a remote thread in the target process to load the DLL.
  - `LoadLibrary`: Used by the remote thread to load the DLL into the process.

- **Privileges**: 
  - Typically requires `PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, `PROCESS_CREATE_THREAD`, and `PROCESS_QUERY_INFORMATION` privileges.
  - Administrative privileges may be required if injecting into system processes or processes owned by another user.

### 2. **Process Hollowing**

**Description**: Process hollowing involves creating a process in a suspended state, replacing its code with malicious code, and then resuming the process.

- **Win32 APIs**:
  - `CreateProcess`: Creates a new process in a suspended state using the `CREATE_SUSPENDED` flag.
  - `ZwUnmapViewOfSection`: Unmaps the original executable code from the process.
  - `VirtualAllocEx`: Allocates memory in the target process for the malicious code.
  - `WriteProcessMemory`: Writes the malicious code into the allocated memory.
  - `SetThreadContext`: Updates the context of the main thread to point to the malicious code.
  - `ResumeThread`: Resumes the main thread, executing the injected code.

- **Privileges**: 
  - Requires the ability to create processes and manipulate their memory (`PROCESS_ALL_ACCESS` or equivalent).
  - Administrative privileges may be required if targeting privileged processes.

### 3. **Thread Execution Hijacking**

**Description**: Thread execution hijacking involves suspending a thread in a target process, modifying its execution context to point to malicious code, and resuming the thread.

- **Win32 APIs**:
  - `OpenThread`: Opens a handle to the target thread.
  - `SuspendThread`: Suspends the thread to modify its context.
  - `GetThreadContext`: Retrieves the thread’s context.
  - `SetThreadContext`: Modifies the thread’s context to point to the malicious code.
  - `ResumeThread`: Resumes the thread, causing it to execute the injected code.

- **Privileges**:
  - Requires `THREAD_SUSPEND_RESUME`, `THREAD_SET_CONTEXT`, and `THREAD_QUERY_INFORMATION` privileges.
  - Administrative privileges may be required if targeting system or protected processes.

### 4. **APC (Asynchronous Procedure Call) Injection**

**Description**: APC injection involves queuing a user-mode APC in the context of a target thread, which executes when the thread enters an alertable state.

- **Win32 APIs**:
  - `OpenThread`: Opens a handle to the target thread.
  - `QueueUserAPC`: Queues an APC in the target thread's APC queue.
  - `VirtualAllocEx`: Allocates memory in the target process for the malicious code.
  - `WriteProcessMemory`: Writes the malicious code into the allocated memory.

- **Privileges**:
  - Requires `THREAD_SET_CONTEXT` and `THREAD_QUERY_INFORMATION` privileges.
  - The target thread must enter an alertable state for the APC to execute (e.g., by calling `SleepEx`, `WaitForSingleObjectEx`, etc.).
  - Administrative privileges may be needed if injecting into higher-privileged processes.

### 5. **Reflective DLL Injection**

**Description**: Reflective DLL injection loads a DLL into a process without using the Windows loader, typically by executing the DLL directly from memory.

- **Win32 APIs**:
  - `VirtualAlloc`: Allocates memory within the current process for the reflective loader.
  - `CreateThread`: Creates a thread to execute the reflective loader.
  - Reflective loader code uses various APIs to perform manual DLL loading (e.g., `GetProcAddress`, `LoadLibrary`).

- **Privileges**:
  - Requires the ability to allocate memory and create threads in the target process.
  - No special privileges are required if injecting into a process owned by the same user.

### 6. **Process Doppelgänging**

**Description**: Process Doppelgänging is a stealthy injection technique that exploits the Windows Transactional NTFS (TxF) feature to inject code into a process without leaving traces on the disk.

- **Win32 APIs**:
  - `CreateTransaction`: Creates a new transaction object.
  - `CreateFileTransacted`: Creates or opens a file as part of a transaction.
  - `NtCreateSection`: Creates a section object for the transaction.
  - `NtMapViewOfSection`: Maps the section into the process’s memory space.
  - `NtQueryInformationProcess`: Modifies process information to replace the legitimate executable image with the malicious one.
  - `NtCreateThreadEx`: Creates a thread to execute the injected code.

- **Privileges**:
  - Requires `PROCESS_CREATE_THREAD`, `PROCESS_VM_OPERATION`, and `PROCESS_VM_WRITE` privileges.
  - Administrative privileges may be required if targeting higher-privileged processes.

### 7. **PE Injection (Portable Executable Injection)**

**Description**: PE injection involves manually mapping a PE file (e.g., EXE or DLL) into the memory of a target process and executing it.

- **Win32 APIs**:
  - `VirtualAllocEx`: Allocates memory in the target process.
  - `WriteProcessMemory`: Writes the PE headers and sections into the target process.
  - `CreateRemoteThread`: Creates a thread to execute the entry point of the injected PE.

- **Privileges**:
  - Requires `PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, and `PROCESS_CREATE_THREAD` privileges.
  - Administrative privileges may be required depending on the target process.

### 8. **Hook Injection**

**Description**: Hook injection involves inserting a hook function into a target process, which redirects the process’s execution flow to malicious code.

- **Win32 APIs**:
  - `SetWindowsHookEx`: Installs a hook procedure into the hook chain.
  - `CallNextHookEx`: Calls the next hook procedure in the chain (used to maintain the hook chain after the malicious code executes).
  - `UnhookWindowsHookEx`: Removes the hook when no longer needed.

- **Privileges**:
  - Requires `PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, and `PROCESS_CREATE_THREAD` privileges.
  - Typically requires administrative privileges to hook system-wide events.

### 9. **Inline Hooking/Function Patching**

**Description**: Inline hooking involves overwriting the beginning of a function in a target process with a jump to the malicious code.

- **Win32 APIs**:
  - `VirtualProtect`: Changes the memory protection on the target function to allow writing.
  - `WriteProcessMemory`: Writes the jump instruction to the target function.
  - `FlushInstructionCache`: Ensures that the CPU’s instruction cache is updated with the modified code.

- **Privileges**:
  - Requires `PROCESS_VM_OPERATION` and `PROCESS_VM_WRITE` privileges.
  - Administrative privileges may be required if targeting system or protected processes.

### 10. **Thread Local Storage (TLS) Callback Injection**

**Description**: TLS callback injection involves adding a malicious TLS callback to a DLL or executable, which executes when the process or DLL is loaded.

- **Win32 APIs**:
  - No specific APIs are required for the injection itself, as the TLS callbacks are executed automatically by the system loader.
  - You may use APIs like `VirtualProtect` and `WriteProcessMemory` to inject the TLS callback into the target executable or DLL.

- **Privileges**:
  - Requires the ability to modify the executable or DLL (typically during the build process).
  - No special privileges are required if injecting into a process owned by the same user.

### Summary of Privileges and Win32 APIs

- **Common Privileges**: 
  - `PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, `PROCESS_CREATE_THREAD`, `PROCESS_QUERY_INFORMATION`, and `PROCESS_SUSPEND_RESUME` are the most common privileges required for these injection techniques.
  - Administrative privileges are often needed when targeting system processes or processes owned by other users.

- **Win32 APIs**: 
  - APIs like `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `NtCreateThreadEx`, `SetThreadContext`, and `QueueUserAPC` are frequently used across different injection techniques.

These injection techniques are widely used in both legitimate software (for example, in debugging and hooking frameworks) and malicious activities (for example, by malware to evade detection and persist on a system). Understanding them is crucial for both defensive and offensive security roles.