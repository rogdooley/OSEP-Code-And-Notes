
To enumerate the possibility of a **Silver Ticket** attack in an Active Directory (AD) environment, the primary focus is on identifying accounts or services that use **service principal names (SPNs)** and checking for accounts with **service delegation** privileges, especially if these accounts have weak or guessable passwords. Here are methods and tools that can be used:

### 1. **Enumerate SPNs (Service Principal Names)**

A Silver Ticket attack targets specific services by forging Kerberos tickets, so it’s important to find accounts associated with SPNs.

- **PowerView**:
  ```powershell
  Get-DomainUser -SPN
  ```

- **Active Directory PowerShell Module**:
  ```powershell
  Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
  ```

  This command lists all users with an SPN. Focus on accounts tied to critical services like `HTTP`, `MSSQL`, `CIFS`, and `HOST`.

### 2. **Check for Weak or Guessable Passwords on Service Accounts**
   Attackers can exploit weak passwords for accounts associated with SPNs. Password spraying techniques can help identify weak credentials.

- **CrackMapExec (CME)**:
  ```bash
  cme smb <target_IP> -u <username> -p <password>
  ```
  
  Use this command to test weak or guessable passwords for service accounts.

### 3. **Enumerate Permissions for Service Accounts**
   Accounts that can perform Kerberos delegation (like `TrustThisComputerForDelegation`) are prime targets for Silver Ticket attacks.

- **PowerView**:
  ```powershell
  Get-DomainUser -TrustedToAuth
  ```

  This command lists users with **Trusted to Authenticate for Delegation** permissions. If an attacker compromises such an account, they can forge Kerberos tickets for any service.

- **ADSI PowerShell**:
  ```powershell
  Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation
  ```

### 4. **Check for Kerberos Delegation Misconfigurations**
   Kerberos delegation can open up the possibility of forging Silver Tickets if not properly configured.

- **PowerView**:
  ```powershell
  Get-DomainUser -TrustedToAuth | Get-DomainComputer
  ```

  This helps find accounts with delegation privileges for computers, indicating they can access sensitive services.

### 5. **Dump Service Ticket (TGS) Hashes for Brute Forcing (Kerberoasting)**

By kerberoasting service accounts with SPNs, you can attempt to crack their hashes. Weak passwords make it easy to exploit them with a Silver Ticket attack.

- **Rubeus**:
  ```bash
  Rubeus.exe kerberoast
  ```

- **PowerView**:
  ```powershell
  Get-DomainSPNTicket
  ```

### 6. **Look for Unconstrained Delegation**
   Accounts with **unconstrained delegation** can be a big risk. Attackers can impersonate any user and forge tickets for various services.

- **PowerView**:
  ```powershell
  Get-DomainComputer -Unconstrained
  ```

  This lists computers that have unconstrained delegation enabled. These are prime targets for Silver Ticket attacks.

### 7. **List Group Memberships**
   Privileged accounts or service accounts with high-level group memberships (like `Domain Admins` or `Enterprise Admins`) are valuable for Silver Ticket attacks.

- **PowerView**:
  ```powershell
  Get-DomainGroupMember -Identity 'Domain Admins'
  ```

### 8. **Manually Check Account Permissions**
   Use **Get-DomainObjectAcl** to check what kind of access accounts have over specific service accounts or computers.

- **PowerView**:
  ```powershell
  Get-DomainObjectAcl -TargetUser <target_account>
  ```

### 9. **Dump Service Account Credentials**
   Use Mimikatz or other tools to dump service account credentials, especially for accounts with SPNs.

- **Mimikatz**:
  ```bash
  sekurlsa::tickets
  ```

### Tools for Silver Ticket Enumeration:
- **PowerView**: An essential tool for Active Directory enumeration.
- **BloodHound**: Helps visualize attack paths and find high-value targets for Silver Tickets.
- **Rubeus**: For Kerberos ticket manipulation.
- **Mimikatz**: For dumping credentials and tickets.


Here's an overview of how to **enumerate the possibility of Golden, Diamond, and Sapphire ticket attacks** in Active Directory, along with steps and methods for identifying vulnerabilities related to each attack type.

### 1. **Golden Ticket Attack**
A **Golden Ticket** attack involves forging a Ticket Granting Ticket (TGT) for the KRBTGT account, allowing attackers to impersonate any user in the domain.

#### Steps to Assess Golden Ticket Vulnerability:
- **Identify Domain Admin Accounts**
  The KRBTGT account can only be fully exploited if you have domain administrator privileges or access to the domain controller (DC). Checking for Domain Admins or accounts with high privileges is key.

  - **PowerView**:
    ```powershell
    Get-DomainGroupMember -Identity "Domain Admins"
    ```
  - **Active Directory PowerShell Module**:
    ```powershell
    Get-ADGroupMember -Identity "Domain Admins"
    ```

- **Dump the KRBTGT Hash**
  Golden Ticket attacks rely on the **KRBTGT** account's NTLM hash. If you can dump this, you're able to forge TGTs.
  
  - **Mimikatz**:
    ```bash
    lsadump::lsa /inject /name:krbtgt
    ```
    This will dump the **KRBTGT** hash, which can be used to create Golden Tickets.

- **Check for Reused KRBTGT Hashes**
  If the KRBTGT password hasn’t been reset in a long time, it could be used to forge tickets across long periods. You can check for how long it has been since the KRBTGT password was reset.

  - **PowerShell**:
    ```powershell
    Get-ADUser -Identity krbtgt -Properties PasswordLastSet
    ```

- **Check for Privileged Accounts**
  Golden Ticket attacks are often launched after compromising privileged accounts. You can enumerate accounts with elevated privileges.

  - **PowerView**:
    ```powershell
    Get-DomainUser -AdminCount 1
    ```

### 2. **Diamond Ticket Attack**
A **Diamond Ticket** attack involves forging Service Tickets (TGS) for **non-Windows services** like Linux or other services that use Kerberos for authentication but aren’t directly tied to Active Directory.

#### Steps to Assess Diamond Ticket Vulnerability:
- **Find Service Principal Names (SPNs) for Non-Windows Services**
  The first step is to locate services that use Kerberos but are not part of Windows.

  - **PowerView**:
    ```powershell
    Get-DomainUser -SPN
    ```

  - **Active Directory PowerShell Module**:
    ```powershell
    Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
    ```

  Look for non-Windows services (e.g., Linux or Unix systems running services like HTTP, NFS, etc.) in the SPNs.

- **Compromise Service Accounts for Non-Windows Services**
  If non-Windows service accounts are using weak or guessable passwords, they can be targeted in the same way as a Kerberoasting attack. Crack the password for these accounts to forge service tickets.

- **Use Service Tickets for Non-Windows Services**
  After obtaining the service account credentials, the attacker can forge a Kerberos Service Ticket (TGS) and use it to authenticate to non-Windows services.

- **Manually Test Non-Windows Services**
  Once service account credentials are cracked, attempt to authenticate directly to the service using the obtained tickets.

### 3. **Sapphire Ticket Attack**
The **Sapphire Ticket** attack is not a common term used widely like Golden or Silver Tickets, but it refers to attacks where the **Public Key Infrastructure (PKI)** in Active Directory is compromised, allowing the attacker to forge Public Key (PK) tickets. This can enable long-term access without needing the KRBTGT hash.

#### Steps to Assess Sapphire Ticket Vulnerability:
- **Enumerate PKI Certificates in the Environment**
  First, enumerate what certificate authorities (CAs) are in use and which users or services are leveraging certificates for authentication.

  - **Certutil**:
    ```bash
    certutil -ca.cert
    ```

- **Identify Weak PKI Configurations**
  Weak or misconfigured PKI setups, especially if the CA's private key is exposed, can be exploited to issue valid tickets or certificates for any user.

  - **ADCS Enumeration**:
    Check for misconfigurations in the **Active Directory Certificate Services (ADCS)** or any overly permissive issuance of certificates.
  
- **Enumerate Certificate Templates**
  By enumerating certificate templates, attackers can see what kinds of certificates are issued and for whom.

  - **PowerShell**:
    ```powershell
    Get-CertificateTemplate
    ```

- **Compromise a Certificate Authority (CA)**
  If attackers compromise a CA, they can issue valid certificates for any user or service, similar to a Golden Ticket but using PKI instead of Kerberos tickets.

  - **Certutil**:
    ```bash
    certutil -config -view
    ```

### Tools to Help Identify These Vulnerabilities:
- **PowerView**: For domain enumeration, including SPNs, users, and privileges.
- **BloodHound**: For identifying attack paths and relationships between users, computers, and SPNs that could lead to ticketing attacks.
- **Rubeus**: For interacting with Kerberos tickets, including forging tickets (Golden, Silver) or extracting hashes (Kerberoasting).
- **Mimikatz**: For dumping credentials, especially the KRBTGT hash for Golden Tickets, or interacting with certificates and tickets.
- **ADCS** tools: For enumerating and assessing the state of the Active Directory Certificate Services (ADCS).

### Quick Summary:
- **Golden Ticket**: Exploits the KRBTGT account to forge TGTs for any user.
  - Tools: Mimikatz, PowerView, BloodHound.
  
- **Diamond Ticket**: Focuses on forging tickets for non-Windows services using Kerberos.
  - Tools: PowerView, Rubeus.
  
- **Sapphire Ticket**: Involves compromising PKI and forging certificates to authenticate as any user.
  - Tools: Certutil, Mimikatz, ADCS tools.
