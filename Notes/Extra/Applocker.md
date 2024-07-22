
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