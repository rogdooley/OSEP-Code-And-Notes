# Output file
$outputFile = "windows_enum_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

# Function to log output
function Log-Output {
    param (
        [string]$message,
        [string]$color = "White"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $coloredMessage = $message
    Write-Host "$timestamp - $coloredMessage" -ForegroundColor $color
    Add-Content -Path $outputFile -Value "$timestamp - $message"
}

# Header
Log-Output "===== Windows Enumeration Script =====" "Cyan"

# 1. Basic System Information
Log-Output "[+] Basic System Information" "Green"
Log-Output "Hostname: $(hostname)" "Yellow"
Log-Output "OS Version: $(Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty Version)" "Yellow"
Log-Output "System Architecture: $([System.Environment]::Is64BitOperatingSystem)" "Yellow"
Log-Output "System Uptime: $(Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty LastBootUpTime)" "Yellow"
Log-Output "Logged in User: $(whoami)" "Yellow"
Log-Output ""

# 2. Network Configuration
Log-Output "[+] Network Configuration" "Green"
Log-Output "IP Configuration:" "Yellow"
Get-NetIPAddress | Format-Table -AutoSize | Out-String | ForEach-Object { Log-Output $_ }
Log-Output "Routing Table:" "Yellow"
Get-NetRoute | Format-Table -AutoSize | Out-String | ForEach-Object { Log-Output $_ }
Log-Output "DNS Configuration:" "Yellow"
Get-DnsClientServerAddress | Format-Table -AutoSize | Out-String | ForEach-Object { Log-Output $_ }
Log-Output "Active TCP Connections:" "Yellow"
Get-NetTCPConnection | Format-Table -AutoSize | Out-String | ForEach-Object { Log-Output $_ }
Log-Output ""

# 3. User and Group Information
Log-Output "[+] User and Group Information" "Green"
Log-Output "Current User: $(whoami)" "Yellow"
Log-Output "User Groups: " "Yellow"
(Get-LocalUser | Where-Object { $_.Enabled -eq $true }).Name | ForEach-Object { Log-Output $_ }
Log-Output "List of Users:" "Yellow"
Get-LocalUser | Format-Table -AutoSize | Out-String | ForEach-Object { Log-Output $_ }
Log-Output "List of Groups:" "Yellow"
Get-LocalGroup | Format-Table -AutoSize | Out-String | ForEach-Object { Log-Output $_ }
Log-Output ""

# 4. Running Processes
Log-Output "[+] Running Processes" "Green"
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 | Format-Table -AutoSize | Out-String | ForEach-Object { Log-Output $_ }
Log-Output ""

# 5. Services
Log-Output "[+] Services" "Green"
Log-Output "Running Services:" "Yellow"
Get-Service | Where-Object { $_.Status -eq 'Running' } | Format-Table -AutoSize | Out-String | ForEach-Object { Log-Output $_ }
Log-Output ""

# 6. Scheduled Tasks
Log-Output "[+] Scheduled Tasks" "Green"
Get-ScheduledTask | Where-Object { $_.State -eq 'Ready' } | Format-Table -AutoSize | Out-String | ForEach-Object { Log-Output $_ }
Log-Output ""

# 7. PowerShell Command History
Log-Output "[+] PowerShell Command History" "Green"
$historyPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $historyPath) {
    Log-Output "PowerShell Command History:" "Yellow"
    Get-Content $historyPath | ForEach-Object { Log-Output $_ }
} else {
    Log-Output "No PowerShell command history found." "Yellow"
}
Log-Output ""

# 8. Documents Folder Enumeration
Log-Output "[+] Documents Folder Enumeration" "Green"
$documentsPath = [environment]::GetFolderPath('MyDocuments')
if (Test-Path $documentsPath) {
    Log-Output "Listing files in Documents folder:" "Yellow"
    Get-ChildItem -Path $documentsPath -Recurse -File | Format-Table Name, Length, LastWriteTime -AutoSize | Out-String | ForEach-Object { Log-Output $_ }
} else {
    Log-Output "Documents folder not found." "Yellow"
}
Log-Output ""

# 9. Search for Sensitive Files
Log-Output "[+] Searching for Sensitive Files (SSH keys, Web Config Files, etc.)" "Green"
$searchPaths = @(
    "$env:USERPROFILE\.ssh\id_rsa",
    "$env:USERPROFILE\.ssh\id_rsa.pub",
    "$env:USERPROFILE\Documents\web.config",
    "$env:USERPROFILE\Desktop\web.config",
    "C:\inetpub\wwwroot\web.config"
)

foreach ($path in $searchPaths) {
    if (Test-Path $path) {
        Log-Output "Found: $path" "Yellow"
    } else {
        Log-Output "Not found: $path" "Yellow"
    }
}
Log-Output ""

# Finalization
Log-Output "===== Enumeration Complete =====" "Cyan"
Log-Output "Results saved to $outputFile" "Cyan"
