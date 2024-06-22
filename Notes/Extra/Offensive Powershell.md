- https://www.bordergate.co.uk/offensive-powershell/
- Much of the utility of PowerShell is in it’s ability to execute .NET code within a PowerShell session. In turn, this .NET code can execute native Win32 functions by using System.Runtime.InteropServices.


In PowerShell, an assembly refers to a .NET assembly, which is a compiled code library that contains classes, interfaces, structures, enums, and other types. .NET assemblies are typically stored in files with the extension `.dll` or `.exe`. Here's what you need to know about assemblies in PowerShell:

1. **Loading Assemblies**: PowerShell allows you to load .NET assemblies into your session using the `Add-Type` cmdlet. This cmdlet allows you to load assemblies from files, byte arrays, or from the global assembly cache (GAC).
    
    Example:
    `Add-Type -AssemblyName System.Drawing`
    
2. **Using Types from Assemblies**: Once an assembly is loaded, you can use types (classes, enums, etc.) defined in that assembly in your PowerShell scripts or commands.
    
    Example:

    `# Create an instance of a .NET class from the loaded assembly $bitmap = New-Object System.Drawing.Bitmap(100, 100)`
    
3. **Manipulating Assemblies**: PowerShell provides cmdlets and functions for working with assemblies, such as `Get-ChildItem`, `Import-Module`, and `Remove-Module`.
    
4. **Dynamic Assembly Generation**: PowerShell also supports dynamically generating assemblies at runtime using the `Add-Type` cmdlet with script blocks or source code strings.
    
    Example:
    
    `$assemblyCode = @" public class MyTestClass {     public void HelloWorld() {         Write-Host 'Hello, World!'     } } "@  Add-Type -TypeDefinition $assemblyCode`
    
5. **Accessing Assembly Information**: You can access information about loaded assemblies using the `Get-Assembly` cmdlet or by using .NET types and methods directly.
    
    `[System.AppDomain]::CurrentDomain.GetAssemblies()`
    

Overall, assemblies in PowerShell provide access to a wide range of .NET functionality and allow you to extend the capabilities of PowerShell scripts by leveraging the rich set of .NET libraries available in the .NET framework.

A function pointer, also called a subroutine pointer or procedure pointer, is **a pointer referencing executable code, rather than data**.

#### 32-bit vs 64-bit reference notes:

In this revised version, I've adjusted the data types to use their 64-bit equivalents (`UIntPtr` instead of `IntPtr` and `UInt32` instead of `Int32`). Additionally, I've updated the `LookupFunc` function to locate `kernel32.dll` in the `SysWOW64` folder. However, please note that some Win32 API functions may have different signatures or behaviors in a 64-bit environment, so thorough testing is essential to ensure compatibility.


### Powershell v5 ignore ssl cert

```powershell
add-type @"
>>     using System.Net;
>>     using System.Security.Cryptography.X509Certificates;
>>     public class TrustAllCertsPolicy : ICertificatePolicy {
>>         public bool CheckValidationResult(
>>             ServicePoint srvPoint, X509Certificate certificate,
>>             WebRequest request, int certificateProblem) {
>>             return true;
>>         }
>>     }
>> "@
>> [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
```

### Find 32-bit and 64-bit processes

- https://superuser.com/questions/285413/is-there-a-windows-command-that-returns-the-list-of-64-and-32-process
```powershell
[System.Diagnostics.Process[]] $processes64bit = @()
[System.Diagnostics.Process[]] $processes32bit = @()

  

foreach($process in get-process) {
    $modules = $process.modules
    foreach($module in $modules) {
        $file = [System.IO.Path]::GetFileName($module.FileName).ToLower()
        if($file -eq "wow64.dll") {
            $processes32bit += $process
            break
        }
    }

    if(!($processes32bit -contains $process)) {
        $processes64bit += $process
    }
}
  
write-host "32-bit Processes:"
$processes32bit | sort-object Name | format-table Name, Id -auto 
write-host ""
write-host "64-bit Processes:"
$processes64bit | sort-object Name | format-table Name, Id -auto
```