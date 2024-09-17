
### AMSI and Defender Overview

#### 1. **AMSI (Antimalware Scan Interface)**
   AMSI is a Windows feature that allows applications and services to integrate with antivirus and antimalware products to detect and block malicious code. It is primarily designed to work with scripting engines like **PowerShell**, **JavaScript**, and **VBScript**, allowing these interpreters to send the code to the **AMSI provider** (like **Windows Defender**) for analysis before it executes. It helps prevent attacks like script-based malware or obfuscated PowerShell commands.

   - **Separate Role**: AMSI works as a scanner for applications that integrate with it, analyzing memory buffers before execution, even before the malware can run.
   - **In Conjunction**: AMSI and Defender work together when Defender is the registered **AMSI provider**. AMSI detects suspicious code, sends it to Defender for scanning, and Defender can block it if found malicious.

#### 2. **Windows Defender (Defender Antivirus)**
   Windows Defender (now called **Microsoft Defender Antivirus**) provides protection against malware by using signature-based detection, heuristic analysis, behavior monitoring, and machine learning. It can scan files, memory, and processes in real-time.

   - **Separate Role**: Defender can work without AMSI by using signatures and heuristics to detect and stop malware from running. It focuses on protecting the system by scanning files and processes and detecting malicious patterns.
   - **In Conjunction**: When integrated with AMSI, Defender gets enhanced visibility into memory buffers and script execution, especially useful for **in-memory** or **fileless** malware detection.

### Bypassing AMSI and Defender

#### **Bypassing AMSI**
Memory overwriting is **not always needed** to bypass AMSI. AMSI operates by scanning buffers of code sent to it, meaning that bypass methods can be implemented in different ways depending on the situation. Here are some common bypass methods:

- **Memory Patch (AMSI DLL in-memory patching)**: 
  This involves overwriting certain bytes in the memory where **AMSI.dll** is loaded to prevent the scanning function from working. By modifying the return value of `AmsiScanBuffer`, you can essentially stop AMSI from scanning.
  
  ```csharp
  [DllImport("kernel32.dll")]
  static extern IntPtr GetModuleHandle(string lpModuleName);

  [DllImport("kernel32.dll", SetLastError = true)]
  static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

  var amsiAddr = GetProcAddress(GetModuleHandle("amsi.dll"), "AmsiScanBuffer");
  byte[] patch = { 0x31, 0xC0, 0xC3 }; // XOR EAX,EAX; RET
  WriteProcessMemory(Process.GetCurrentProcess().Handle, amsiAddr, patch, (uint)patch.Length, out var _);
  ```

- **PowerShell Reflection**: 
  Use PowerShell's reflection capabilities to overwrite AMSI functions in-memory dynamically.

  ```powershell
  [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils') | 
      Get-Field 'amsiInitFailed' -BindingFlags NonPublic,Static | 
      Set-Value $true
  ```

- **Obfuscation and Encoding**:
  Obfuscating or encoding the script makes it harder for AMSI to detect malicious content. Obfuscated scripts (like base64 encoding) are still scanned by AMSI, but it makes evasion easier when combined with other techniques.

#### **Bypassing Windows Defender**
Bypassing Defender typically involves evading the detection methods Defender uses, such as real-time scanning, heuristic analysis, and memory analysis.

- **Disabling Defender via PowerShell**: 
  While it’s not always an option on hardened systems, if the system allows it, you can use PowerShell commands to disable parts of Defender (requires admin privileges).

  ```powershell
  Set-MpPreference -DisableRealtimeMonitoring $true
  ```

- **Binary Obfuscation (Packing)**: 
  Malware can be packed or obfuscated to avoid signature-based detection. Packers compress or encrypt the malware and unpack it at runtime.

- **Code Injection**: 
  Using API calls to inject code into trusted processes (like `explorer.exe`) can evade Defender’s process-based detection.

  Example: Using **`CreateRemoteThread`** and **`WriteProcessMemory`** to inject a payload.

  ```csharp
  // Write shellcode to a remote process and execute it
  WriteProcessMemory(hProcess, allocatedMemAddress, shellcode, shellcode.Length, out _);
  CreateRemoteThread(hProcess, IntPtr.Zero, 0, allocatedMemAddress, IntPtr.Zero, 0, IntPtr.Zero);
  ```

- **Living-off-the-land (LOLbins)**: 
  Utilizing legitimate system tools like **MSBuild**, **Regsvr32**, or **Rundll32** to execute malicious payloads in a way that bypasses traditional AV detection.

  ```cmd
  msbuild /p:Configuration=Release malicious.xml
  ```

- **Fileless Malware**: 
  Avoiding touching the disk entirely by executing code directly from memory, which can bypass Defender’s file-based scanning methods.

### Memory Overwriting for AMSI Bypass

While memory overwriting is a common method to bypass AMSI (e.g., patching **`AmsiScanBuffer`** in-memory), it is **not always necessary**. Other techniques such as **reflection-based bypasses**, **obfuscation**, and **disabling AMSI initialization** via PowerShell reflection or COM objects can also bypass AMSI without modifying the memory directly.

### Methods to Bypass AMSI and Defender

| **Bypass Method**               | **Description**                                                       | **API/Technique**                                             |
|----------------------------------|-----------------------------------------------------------------------|---------------------------------------------------------------|
| **AMSI Memory Patch**            | Overwriting `AmsiScanBuffer` function to disable scanning              | `WriteProcessMemory`, `GetProcAddress`                        |
| **PowerShell AMSI Reflection**   | Setting `amsiInitFailed` to true to prevent scanning                   | PowerShell Reflection (`[Ref].Assembly.GetType`)              |
| **Obfuscation**                  | Encoding or obfuscating payload to avoid AMSI detection                | Base64 encoding, string obfuscation                           |
| **Disabling Defender**           | Disabling Defender’s real-time scanning via PowerShell                 | `Set-MpPreference -DisableRealtimeMonitoring $true`           |
| **Process Injection**            | Injecting malicious code into trusted processes to avoid detection     | `CreateRemoteThread`, `WriteProcessMemory`, `VirtualAllocEx`  |
| **Fileless Execution**           | Executing code from memory without touching disk (common in malware)   | Reflective DLL injection, shellcode injection                 |
| **Living-off-the-Land**          | Using trusted Windows utilities to execute payloads                    | `msbuild`, `regsvr32`, `rundll32`                             |
| **Binary Obfuscation/Packing**   | Packing malware to evade static detection by Defender                  | Custom packers, encryption                                    |
| **Disabling AMSI via COM**       | Using COM object hijacking to disable AMSI scanning                    | COM objects (`New-Object`)                                    |

### Summary
- **AMSI** and **Windows Defender** work both separately and in conjunction to protect against malware, especially script-based and in-memory threats.
- Bypassing AMSI doesn’t always require memory overwriting; PowerShell reflection, obfuscation, and COM hijacking are alternatives.
- **Defender** can be bypassed through a range of techniques like obfuscation, living-off-the-land binaries, process injection, and packing.
- The table outlines key methods and Win32 APIs or techniques for bypassing these protections.

### **Mark of the Web (MOTW): Overview**

**Mark of the Web (MOTW)** is a security feature in Windows that marks files as originating from the internet or other untrusted locations (like email attachments or network shares). When a file is downloaded from the internet or comes from an untrusted source, it receives this marker to indicate that it may be unsafe. Files with MOTW are treated with more caution by Windows, triggering warnings and additional checks by security features like **Windows Defender** and **AppLocker**.

### **File Types That Receive MOTW**

By default, the following file types can receive the **Mark of the Web**:

1. **Executables**: `.exe`, `.dll`, `.scr`, `.bat`, `.cmd`, `.msi`
2. **Documents**: `.docx`, `.pptx`, `.xlsx`, `.pdf`, `.rtf`, `.odt`
3. **Compressed files**: `.zip`, `.rar`, `.7z`, `.cab`
4. **Scripts**: `.js`, `.vbs`, `.ps1`, `.html`
5. **Image files** (in certain scenarios): `.jpg`, `.png`, `.gif` (only under specific circumstances, like when embedded in other files or downloaded as part of HTML)

These file types are generally considered potentially harmful because they can contain executable content or macros that might be abused by attackers.

### **File Types That Do Not Receive MOTW**

Some file types do not typically receive MOTW when downloaded, including:

1. **Plain text files**: `.txt`
2. **Non-executable image files**: `.bmp`, `.tiff`
3. **Audio/Video files**: `.mp3`, `.mp4`, `.avi`, `.wav`
4. **Uncompiled code**: `.cpp`, `.py`, `.c`

These types of files are considered safer since they are generally not executable or do not contain executable content directly.

---

### **How Does MOTW Influence Security Checks?**

#### **1. Windows Defender and MOTW**

When a file carries the Mark of the Web, **Windows Defender** and other antivirus programs tend to scan it more rigorously. Windows treats files with MOTW as potentially dangerous, so the following behaviors might occur:

- **Blocked execution**: Executables like `.exe` files are blocked by SmartScreen or prompted with a warning.
- **Deeper scanning**: Windows Defender performs more thorough scans on files with MOTW, prioritizing their analysis.
- **Office documents**: For files like `.docx` or `.xlsx`, macros may be disabled by default, and the user is prompted to enable them after being warned of potential risk.

Without the MOTW, a file may not receive this heightened scrutiny, although routine malware scanning is still performed by Defender.

#### **2. AMSI (Antimalware Scan Interface) and MOTW**

**AMSI** is a security interface used to provide real-time scanning for code and scripts before they are executed. When it comes to files and documents, AMSI primarily applies to **scripts**, such as PowerShell, JavaScript, or VBA macros in Office files.

- **AMSI’s role**: AMSI comes into play when scripts are executed, regardless of the presence of the MOTW. For example, if a `.ps1` file is run, AMSI scans the content before execution, whether or not it has the MOTW.
- **MOTW and AMSI**: The MOTW doesn’t directly control AMSI’s functionality. AMSI is more about analyzing scripts during execution, while MOTW is about the origin of the file and influences whether the file is initially trusted or not.
  
#### **3. Are Files Without MOTW Analyzed?**

- **Windows Defender**: Yes, files without the MOTW are still scanned by Windows Defender, though they may not trigger the same warnings or deep scrutiny as files with MOTW.
  
- **AMSI**: AMSI will still scan scripts like PowerShell or VBA macros during execution, regardless of MOTW. For instance, a malicious PowerShell script will trigger AMSI even if it does not have a MOTW.

- **Office Documents without MOTW**: Office files without MOTW (e.g., opened from trusted local folders) may not trigger certain warnings (such as disabling macros by default). However, they will still be subject to some scanning by Windows Defender and any configured enterprise protections.

---

### **Summary of Key Points**:

- **File Types Receiving MOTW**: Executables, documents, scripts, and some compressed files get MOTW. They trigger extra scrutiny by Windows Defender and SmartScreen.
  
- **Files without MOTW**: Still analyzed, but with less scrutiny. Routine malware scanning is performed by Defender, and AMSI checks scripts when executed, regardless of MOTW.

- **MOTW vs. AMSI**: MOTW indicates file origin and prompts initial trust decisions, while AMSI scans scripts during runtime, regardless of MOTW. Both contribute to system security but in different stages.

In short, MOTW is critical for initial file security assessments, while AMSI handles runtime script scanning independently of MOTW.