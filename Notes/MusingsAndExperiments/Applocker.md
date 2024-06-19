
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