Compromising Active Directory (AD) forests can be a sophisticated process that involves exploiting trust relationships, misconfigurations, and privilege escalation paths within AD. The following outlines common tactics, techniques, and PowerShell-based examples attackers might use to exploit vulnerabilities in AD forests.

### **1. Understanding Active Directory Trusts**

Before we dive into compromising AD forests, it's important to understand **AD trust relationships**. A trust allows users in one AD domain or forest to access resources in another domain or forest.

- **Intra-Forest Trusts**: Trusts between domains within the same forest (implicitly bidirectional).
- **Inter-Forest Trusts**: Trusts between two separate forests (can be one-way or two-way).

By abusing these trusts, attackers can pivot from one domain or forest to another to gain control over an entire environment.

### **2. Reconnaissance**

Attackers often begin by mapping out the environment to discover domains, trust relationships, and privileges. Here’s how PowerShell can be used for reconnaissance in AD:

#### **Get-ADTrust** – Enumerating Trusts
To identify domain or forest trusts, attackers might use the `Get-ADTrust` cmdlet to gather information about AD trust relationships.

```powershell
Get-ADTrust -Filter *
```

This command retrieves all trusts for the current domain, providing key information such as the type of trust and direction (i.e., one-way or two-way). 

Alternatively, attackers can enumerate trust relationships using **PowerView**, a PowerShell tool for AD enumeration:

```powershell
# Using PowerView to enumerate trusts
Get-NetForestTrust
```

---

### **3. Abuse of Trust Relationships**

Once attackers discover trust relationships, they may try to exploit them by performing attacks such as **SID History Injection** and **Kerberos Ticket Forging**.

#### **a) SID History Injection**

**Security Identifier (SID) History** is an attribute in AD that stores the SIDs of previous accounts when migrating accounts between domains. Attackers can inject SIDs into this attribute to impersonate privileged users.

PowerShell can be used alongside `mimikatz` to inject SID history:

```powershell
# Using mimikatz for SID History Injection
Invoke-Mimikatz -Command '"lsadump::sid /domain:target_domain /sid:source_domain"'
```

Once the SID history is injected, attackers can impersonate users across trust boundaries and escalate privileges across domains or forests.

---

#### **b) Kerberos Ticket Forging (Golden Tickets)**

A **Golden Ticket** attack allows attackers to forge a Ticket Granting Ticket (TGT) and impersonate any user, including domain admins, in the forest. Attackers need the **KRBTGT** hash from the target domain to create a golden ticket.

##### Step 1: Dump the KRBTGT hash

```powershell
# Using mimikatz to dump KRBTGT hash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:krbtgt"'
```

##### Step 2: Forge the Golden Ticket

With the KRBTGT hash, attackers can use `mimikatz` to generate a TGT for any user:

```powershell
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:target.com /sid:S-1-5-21-xxxx /krbtgt:<krbtgt_hash> /id:500"'
```

This command forges a TGT for the **Administrator** user in the target domain.

##### Step 3: Pass the Ticket

Once the ticket is created, attackers can inject the TGT into their session:

```powershell
Invoke-Mimikatz -Command '"kerberos::ptt <path_to_tgt>"'
```

This attack allows lateral movement within the forest.

---

### **4. Cross-Forest Attacks**

#### **a) Exploiting Unconstrained Delegation**

Unconstrained delegation allows a service account or computer to impersonate any user by obtaining their TGT. Attackers can abuse this to move laterally and compromise resources in trusted forests.

Attackers can find accounts with unconstrained delegation using PowerShell:

```powershell
Get-ADObject -Filter {userAccountControl -band 0x80000} -Properties Name, userAccountControl
```

Once an attacker identifies a system with unconstrained delegation, they can use it to steal TGTs and impersonate users:

```powershell
# Using Rubeus to dump Kerberos tickets from a system with unconstrained delegation
Invoke-Rubeus -Command "dump"
```

---

#### **b) Exploiting Kerberos Delegation (S4U2Self & S4U2Proxy)**

With constrained delegation, attackers can abuse the **S4U2Self** and **S4U2Proxy** extensions of Kerberos to impersonate users in another domain or forest.

##### Example of abusing S4U2Self:

```powershell
Invoke-Rubeus -Command "s4u /user:attacker_account /impersonateuser:Administrator /domain:target_domain"
```

In this example, the attacker impersonates the `Administrator` in the trusted forest and can request service tickets on behalf of the user.

---

### **5. DCSync Attack**

Attackers with replication privileges in the AD forest can perform a **DCSync attack** to extract credentials from the domain, including those of high-value accounts like domain admins and the KRBTGT account.

```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:Administrator"'
```

This command requests the password hash for the `Administrator` user from the domain controller using the DCSync replication privileges.

---

### **6. Pivoting Between Domains**

After compromising a domain in a trusted forest, attackers can pivot to other domains. By forging tickets or abusing delegation rights, attackers can authenticate across domains, gaining control over the entire forest.

#### Example of Pivoting with Rubeus (Pass-the-Ticket):

```powershell
# Pass the Kerberos ticket to pivot between domains
Invoke-Rubeus -Command "ptt <path_to_ticket>"
```

By injecting the TGT from one domain, attackers can authenticate to services and resources in the trusted domain or forest.

---

### **7. Mitigations**

Mitigating attacks in AD forests involves hardening trust relationships and monitoring for suspicious activity:

- **Limit delegation**: Constrained delegation should only be applied where absolutely necessary, and unconstrained delegation should be avoided.
- **Monitor for ticket usage**: Regularly audit Kerberos tickets and event logs for unusual ticket-granting service (TGS) requests.
- **Use the principle of least privilege**: Ensure service accounts have minimal access and are monitored for abuse.
- **Implement monitoring tools**: Use tools like **ATA** (Advanced Threat Analytics) or **Azure AD Identity Protection** to detect abnormal account behavior.

---

### **Conclusion**

PowerShell provides attackers with a wide range of options to compromise AD forests by abusing trust relationships, delegation, and Kerberos. Key techniques such as **Golden Ticket** attacks, **SID history abuse**, and **DCSync** can allow attackers to move laterally, escalate privileges, and dominate an entire AD forest if not properly secured.

## Extra SIDs attack

An **Extra SIDs Attack** involves adding additional SIDs (Security Identifiers) to a **Kerberos ticket** to impersonate other users or groups, granting unauthorized access to resources. The attack leverages the fact that in Active Directory (AD), some services, like file shares or databases, check group memberships via SIDs in the Kerberos tickets. This means an attacker with the ability to forge or modify a ticket can add extra SIDs to escalate privileges.

### Key Concepts:
- **SID**: A unique identifier assigned to every user, group, and computer account in AD.
- **TGT (Ticket-Granting Ticket)**: A Kerberos ticket used to authenticate to other services. 
- **PAC (Privilege Attribute Certificate)**: A part of the Kerberos ticket that contains user information, such as group memberships.

The **Extra SIDs Attack** works by adding SIDs for privileged groups (like **Domain Admins**) to the **PAC** of a **Kerberos Service Ticket (TGS)**, tricking services into granting unauthorized access.

### Steps in the Attack:

1. **Obtain a Kerberos Ticket**: You need access to an existing Kerberos ticket, usually from a low-privileged user.

2. **Modify the Ticket**: The attack modifies the PAC of the Kerberos ticket to include extra SIDs for privileged groups.

3. **Use the Modified Ticket**: The attacker then uses the modified ticket to access resources that check the SID information, thus escalating privileges.

---

### Tools:
- **Rubeus**: A tool that can manipulate Kerberos tickets, including adding extra SIDs.
- **Impacket**: Used to generate or manipulate Kerberos tickets, useful for forging or injecting tickets.

---

### Working Example of an Extra SIDs Attack Using Rubeus

Here’s an example using **Rubeus** to perform the attack. In this scenario, you already have access to a Kerberos **TGT** for a low-privileged user.

#### Prerequisites:
1. **Rubeus** and **Mimikatz** are available on the target system.
2. A **Kerberos TGT** for a low-privileged user is obtained.

#### Steps:

##### 1. Extract the Kerberos TGT:
Use **Mimikatz** to extract a low-privileged user’s Kerberos **TGT**:
```powershell
mimikatz.exe
kerberos::list /export
```
This exports the TGT as a `.kirbi` file, which will be modified later.

##### 2. Add Extra SIDs to the Ticket:
Use **Rubeus** to modify the ticket and add extra SIDs. In this case, we are adding the **Domain Admins SID** (`S-1-5-21-<Domain>-512`) to the **PAC**.

Example command:
```powershell
Rubeus.exe tgt::sids /ticket:<TGT.kirbi> /sids:S-1-5-21-<Domain>-512 /domain:<domain> /user:<low-priv-user> /rc4:<ntlm_hash> /ptt
```
- `/ticket`: Specifies the ticket you exported.
- `/sids`: The SID(s) you want to add. In this case, the SID for Domain Admins.
- `/ptt`: Pass-the-ticket. This injects the modified ticket into the current session.

##### 3. Verify the Injected Ticket:
To ensure the modified ticket has been injected into your session, use:
```powershell
klist
```
This lists the Kerberos tickets in the current session. You should see your modified ticket with the added SIDs.

##### 4. Access Resources:
With the modified ticket injected, you can now access resources that require **Domain Admin** privileges. For example:
```powershell
dir \\<server>\C$\
```
This command attempts to list the contents of the **C$ Admin Share** on a remote server, which normally requires elevated privileges.

#### Notes:
- This attack works because the modified **Kerberos ticket** tricks services that only check for the presence of specific SIDs in the ticket.
- Not all services are vulnerable to this attack, but file shares, databases, and similar services that rely on SID-based authorization are prime targets.

---

### Explanation:

1. **Extracting the TGT**: Using **Mimikatz**, you can grab the **Ticket-Granting Ticket** for a legitimate user. This gives you a starting point for the attack.
  
2. **Adding Extra SIDs**: **Rubeus** is used to modify the **PAC** (which holds information about group memberships) by adding the **SID** of a high-privileged group (like **Domain Admins**). This tricks the service into thinking the user belongs to that group.

3. **Using the Modified Ticket**: By injecting this modified ticket into the current session, the attacker can access resources that would normally be restricted to privileged users.

---

### Defensive Measures:
1. **Enable PAC Validation**: Ensure that PAC validation is enabled on all Kerberos services to prevent unauthorized SID changes.
2. **Monitor Kerberos Traffic**: Detect unusual Kerberos ticket modifications, especially when SIDs of privileged groups like **Domain Admins** are added to tickets.
3. **Use Group Policy Settings**: Limit the scope of **SID History** to prevent attackers from adding arbitrary SIDs to Kerberos tickets.
4. **Enable Security Event Auditing**: Configure AD to log and alert on SID history changes.

This example demonstrates the core of the **Extra SIDs Attack** and how to leverage **Rubeus** to perform it. It’s a powerful technique that relies on weak PAC validation and SID-based authorization.