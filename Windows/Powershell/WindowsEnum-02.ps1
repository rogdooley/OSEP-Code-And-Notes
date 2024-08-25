# Set color codes for console output
$red = "Red"
$orange = "DarkYellow"
$yellow = "Yellow"
$blue = "Blue"
$green = "Green"
$default = "White"

# Set the log file path
$logFile = "C:\Windows\Tasks\enumeration_log.txt"
$logOutput = ""

# Function to log and print output
function Log-Output {
    param(
        [string]$message,
        [string]$color = $default
    )
    Write-Host $message -ForegroundColor $color
    $logOutput += $message + "`n"
}

# Enumerate users and groups
Log-Output "Enumerating users and groups..." $blue
$users = Get-LocalUser | Select-Object Name, Enabled, LastLogon
$groups = Get-LocalGroup | Select-Object Name, Description
$users | ForEach-Object { Log-Output "User: $_" $yellow }
$groups | ForEach-Object { Log-Output "Group: $_" $yellow }

# Check for non-standard services
Log-Output "Checking non-standard services..." $blue
$services = Get-Service | Where-Object {$_.StartType -ne 'Automatic' -and $_.Status -ne 'Running'}
$services | ForEach-Object { Log-Output "Service: $_" $orange }

# Check for non-standard tasks
Log-Output "Checking non-standard tasks..." $blue
$tasks = Get-ScheduledTask | Where-Object {$_.State -ne 'Ready' -or $_.TaskPath -notlike '\Microsoft*'}
$tasks | ForEach-Object { Log-Output "Task: $_" $orange }

# Check if anyone is logged into the machine
Log-Output "Checking logged in users..." $blue
$loggedInUsers = quser
$loggedInUsers | ForEach-Object { Log-Output "Logged In User: $_" $green }

# Check for non-standard programs
Log-Output "Checking non-standard programs..." $blue
$programs = Get-WmiObject -Query "SELECT * FROM Win32_Product"
$programs | ForEach-Object { Log-Output "Program: $_" $orange }

# Check PowerShell log files
Log-Output "Checking PowerShell log files..." $blue
$psLogs = Get-ChildItem -Path "C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell*" -Recurse
$psLogs | ForEach-Object { Log-Output "PowerShell Log File: $_" $yellow }

# Check open ports
Log-Output "Checking open ports..." $blue
$ports = netstat -an | Select-String "LISTENING"
$ports | ForEach-Object { Log-Output "Open Port: $_" $yellow }

# Check for possible credentials or SSH keys
Log-Output "Checking for possible credentials or SSH keys..." $blue
$sshKeys = Get-ChildItem -Path "$env:USERPROFILE\.ssh" -Recurse -Force -ErrorAction SilentlyContinue
$sshKeys | ForEach-Object { Log-Output "SSH Key Found: $_" $red }

# Check if Defender is running
Log-Output "Checking if Windows Defender is running..." $blue
$defenderStatus = Get-MpComputerStatus
If ($defenderStatus.AntivirusEnabled) {
    Log-Output "Windows Defender is running." $green
} else {
    Log-Output "[!] Windows Defender is not running." $red
}

# Check if AMSI is enabled
Log-Output "Checking if AMSI is enabled..." $blue
$amsiStatus = Get-Process | Where-Object {$_.ProcessName -eq "amsi"}
If ($amsiStatus) {
    Log-Output "AMSI is running." $green
} else {
    Log-Output "[!] AMSI is not running." $red
}

# Check UAC configuration
Log-Output "Checking UAC configuration..." $blue
$uacStatus = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA"
If ($uacStatus -eq 1) {
    Log-Output "UAC is enabled." $green
} else {
    Log-Output "[!] UAC is not enabled." $red
}

# Check AppLocker configuration and bypass possibilities
Log-Output "Checking AppLocker configuration..." $blue
$applockerStatus = Get-AppLockerPolicy -Effective | Select-String "Appx"
If ($applockerStatus) {
    Log-Output "AppLocker is configured." $green
} else {
    Log-Output "[!] AppLocker is not configured." $red
}

# Try to bypass restricted mode if PowerShell is restricted
Log-Output "Checking for PowerShell Restricted Mode..." $blue
$executionPolicy = Get-ExecutionPolicy
If ($executionPolicy -eq "Restricted") {
    Log-Output "[!] PowerShell is in restricted mode. Attempting bypass..." $red
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
    $bypassStatus = Get-ExecutionPolicy
    If ($bypassStatus -eq "Bypass") {
        Log-Output "Restricted mode bypassed." $green
    } else {
        Log-Output "[!] Failed to bypass restricted mode." $red
    }
}

# Save the log output to a file
$logOutput | Out-File -FilePath $logFile -Force

Log-Output "Enumeration completed. Output saved to $logFile" $blue